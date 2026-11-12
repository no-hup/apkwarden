package io.apkwarden.core.rules

import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import io.apkwarden.core.dex.MethodAnalyzer
import io.apkwarden.core.dex.RegisterValue
import io.apkwarden.core.dex.TaintSource
import io.apkwarden.core.model.Confidence
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.Severity

/**
 * APK-SEC-001: Intent Redirection
 * Exported component forwards received Intent to startActivity/startService/sendBroadcast without validation.
 */
class IntentRedirectionRule : Rule {
    override val id = "APK-SEC-001"
    override val name = "Intent Redirection"
    override val description = "Exported component receives an Intent and forwards it to startActivity, startService, or sendBroadcast without validating the destination component or package."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val startCallSites = context.dexIndex.findCallSites("android.content.Context", "startActivity") +
                context.dexIndex.findCallSites("android.app.Activity", "startActivity") +
                context.dexIndex.findCallSites("android.content.Context", "startService") +
                context.dexIndex.findCallSites("android.content.Context", "sendBroadcast")

        for (cs in startCallSites) {
            val isExported = context.dexIndex.isReachableFromExportedComponent(cs.callerClass, context.attackSurface)
            if (!isExported) continue

            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            // In startActivity(intent), the intent is the 2nd register for virtual calls (register 0 is this, register 1 is Intent)
            val intentReg = if (args.size >= 2) args[1] else continue
            val regVal = analyzer.getRegisterValue(intentReg, cs.instructionIndex)

            val isTainted = when (regVal) {
                is RegisterValue.Tainted -> regVal.source == TaintSource.INTENT_EXTRA || regVal.source == TaintSource.INTENT_OBJECT
                else -> false
            }

            if (isTainted) {
                findings.add(
                    Finding(
                        id = id,
                        title = "Intent Redirection in Exported Component",
                        severity = Severity.CRITICAL,
                        confidence = Confidence.FIRM,
                        cwe = "CWE-926",
                        owasp = "M4: Insufficient Input/Output Validation",
                        description = "Exported class '${cs.callerClass}' forwards an Intent received from external callers directly to '${cs.targetMethod}' without verifying its target package or component.",
                        remediation = "Validate that the forwarded Intent's component package matches your application: `if (forwardIntent.getComponent()?.getPackageName() == getPackageName()) { startActivity(forwardIntent); }` or use explicit Intents.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = "Call to ${cs.targetClass}#${cs.targetMethod} with tainted register v$intentReg ($regVal)",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-002: Mutable PendingIntent
 * PendingIntent created without FLAG_IMMUTABLE on targetSdk >= 31, or explicitly with FLAG_MUTABLE.
 */
class MutablePendingIntentRule : Rule {
    override val id = "APK-SEC-002"
    override val name = "Mutable PendingIntent"
    override val description = "PendingIntent created without FLAG_IMMUTABLE (0x04000000) or explicitly using FLAG_MUTABLE (0x02000000) allows untrusted recipients to modify the intent's action, data, or flags."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val pendingIntentCalls = context.dexIndex.findCallSites("android.app.PendingIntent", "getActivity") +
                context.dexIndex.findCallSites("android.app.PendingIntent", "getBroadcast") +
                context.dexIndex.findCallSites("android.app.PendingIntent", "getService") +
                context.dexIndex.findCallSites("android.app.PendingIntent", "getForegroundService")

        val flagImmutable = 0x04000000
        val flagMutable = 0x02000000

        for (cs in pendingIntentCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            // static method getActivity(context, requestCode, intent, flags) -> args[3] is flags
            if (args.size < 4) continue
            val flagsReg = args[3]
            val regVal = analyzer.getRegisterValue(flagsReg, cs.instructionIndex)

            var isVulnerable = false
            var detail = ""

            when (regVal) {
                is RegisterValue.IntConstant -> {
                    val flags = regVal.value
                    if (flags and flagMutable != 0) {
                        isVulnerable = true
                        detail = "Explicitly uses FLAG_MUTABLE (0x02000000)"
                    } else if (flags and flagImmutable == 0 && context.attackSurface.targetSdk >= 31) {
                        isVulnerable = true
                        detail = "Missing FLAG_IMMUTABLE (0x04000000) on targetSdk ${context.attackSurface.targetSdk}"
                    }
                }
                is RegisterValue.Unknown -> {
                    // If targetSdk >= 31, lack of demonstrable FLAG_IMMUTABLE is suspicious
                    if (context.attackSurface.targetSdk >= 31) {
                        // Check if method contains any reference to 0x04000000
                        val hasImmutableConst = cs.method.implementation?.instructions?.any {
                            it is com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction &&
                                    (it.narrowLiteral and flagImmutable != 0)
                        } ?: false
                        if (!hasImmutableConst) {
                            isVulnerable = true
                            detail = "Flags register resolved to dynamic value without FLAG_IMMUTABLE present in method"
                        }
                    }
                }
                else -> {}
            }

            if (isVulnerable) {
                findings.add(
                    Finding(
                        id = id,
                        title = "Mutable PendingIntent Created",
                        severity = Severity.HIGH,
                        confidence = Confidence.FIRM,
                        cwe = "CWE-926",
                        owasp = "M4: Insufficient Input/Output Validation",
                        description = "PendingIntent created in '${cs.callerClass}#${cs.callerMethod}' is mutable ($detail). Untrusted receiving apps can alter the underlying intent.",
                        remediation = "Use `PendingIntent.FLAG_IMMUTABLE` when creating PendingIntents: `PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE)`.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = detail,
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-003: Implicit PendingIntent
 * PendingIntent wrapping an implicit intent.
 */
class ImplicitPendingIntentRule : Rule {
    override val id = "APK-SEC-003"
    override val name = "Implicit PendingIntent"
    override val description = "PendingIntent wraps an implicit Intent without explicit package or component specification, risking intent interception."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val pendingIntentCalls = context.dexIndex.findCallSites("android.app.PendingIntent", "getActivity") +
                context.dexIndex.findCallSites("android.app.PendingIntent", "getBroadcast") +
                context.dexIndex.findCallSites("android.app.PendingIntent", "getService")

        for (cs in pendingIntentCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            if (args.size < 3) continue
            // Intent is arg 2
            val hasExplicitIntent = analyzer.containsCallTo("android.content.Intent", "setPackage") ||
                    analyzer.containsCallTo("android.content.Intent", "setComponent") ||
                    analyzer.containsCallTo("android.content.Intent", "setClass") ||
                    analyzer.containsCallTo("android.content.Intent", "setClassName")

            if (!hasExplicitIntent) {
                findings.add(
                    Finding(
                        id = id,
                        title = "PendingIntent with Implicit Intent",
                        severity = Severity.MEDIUM,
                        confidence = Confidence.TENTATIVE,
                        cwe = "CWE-926",
                        owasp = "M4: Insufficient Input/Output Validation",
                        description = "PendingIntent created in '${cs.callerClass}#${cs.callerMethod}' wraps an Intent that does not explicitly set package or component destination.",
                        remediation = "Make the wrapped Intent explicit by specifying the target package or component: `intent.setPackage(context.getPackageName())`.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = "Method lacks setPackage/setComponent calls before PendingIntent.${cs.targetMethod}",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-004: Dynamic Receiver Missing Export Flag
 * On targetSdk >= 34, registerReceiver requires RECEIVER_EXPORTED (0x2) or RECEIVER_NOT_EXPORTED (0x4).
 */
class DynamicReceiverExportRule : Rule {
    override val id = "APK-SEC-004"
    override val name = "Dynamic BroadcastReceiver Missing Export Flag"
    override val description = "On Android 14+ (targetSdk >= 34), dynamically registered receivers must explicitly declare RECEIVER_EXPORTED (0x2) or RECEIVER_NOT_EXPORTED (0x4)."

    override fun analyze(context: AnalysisContext): List<Finding> {
        if (context.attackSurface.targetSdk < 34) return emptyList()

        val findings = mutableListOf<Finding>()
        val registerCalls = context.dexIndex.findCallSites("android.content.Context", "registerReceiver") +
                context.dexIndex.findCallSites("android.content.ContextWrapper", "registerReceiver")

        for (cs in registerCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            // Two-parameter version registerReceiver(receiver, filter) has no export flag (args.size == 3 including 'this')
            if (args.size <= 3) {
                findings.add(
                    Finding(
                        id = id,
                        title = "BroadcastReceiver Registered Without Export Flag",
                        severity = Severity.HIGH,
                        confidence = Confidence.CERTAIN,
                        cwe = "CWE-926",
                        owasp = "M4: Insufficient Input/Output Validation",
                        description = "Class '${cs.callerClass}' registers a dynamic BroadcastReceiver without specifying RECEIVER_EXPORTED or RECEIVER_NOT_EXPORTED on targetSdk ${context.attackSurface.targetSdk}. This causes a SecurityException crash or security bypass on Android 14+.",
                        remediation = "Use `ContextCompat.registerReceiver(context, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)`.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = "Call to registerReceiver with ${args.size - 1} parameters (missing export flags)",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-010: Unvalidated Deep Link Host
 * Checks uri.getHost() with .contains() or .endsWith() rather than strict domain match.
 */
class DeepLinkHostValidationRule : Rule {
    override val id = "APK-SEC-010"
    override val name = "Weak Deep Link Host Validation"
    override val description = "Deep link handler validates URI host using .contains() or .endsWith() rather than strict domain matching, allowing subdomain or domain-spoofing bypasses."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val deepLinkActivities = context.attackSurface.deepLinks.map { it.targetComponent }.toSet()

        for (activityName in deepLinkActivities) {
            val classDef = context.dexIndex.classDefs[activityName] ?: continue
            for (method in classDef.methods) {
                val analyzer = MethodAnalyzer(method)
                val hasGetHost = analyzer.containsCallTo("android.net.Uri", "getHost")
                val hasWeakContains = analyzer.containsCallTo("java.lang.String", "contains")
                val hasWeakEndsWith = analyzer.containsCallTo("java.lang.String", "endsWith")

                if (hasGetHost && (hasWeakContains || hasWeakEndsWith)) {
                    findings.add(
                        Finding(
                            id = id,
                            title = "Fragile Deep Link Host Validation",
                            severity = Severity.MEDIUM,
                            confidence = Confidence.FIRM,
                            cwe = "CWE-20",
                            owasp = "M4: Insufficient Input/Output Validation",
                            description = "Deep link handler in '$activityName#${method.name}' inspects Uri host using contains() or endsWith(). Attackers can bypass this check using domains like 'attacker-example.com' or 'example.com.attacker.org'.",
                            remediation = "Validate deep link host against an exact whitelist or require a leading dot: `val host = uri.host ?: return; if (host == \"example.com\" || host.endsWith(\".example.com\")) { ... }`",
                            component = activityName,
                            targetClass = activityName,
                            targetMethod = method.name,
                            evidence = "Method calls Uri.getHost() and String.${if (hasWeakContains) "contains" else "endsWith"}",
                            lineOrOffset = null
                        )
                    )
                }
            }
        }
        return findings
    }
}

/**
 * APK-SEC-019: Overprivileged Dangerous Permissions
 */
class OverprivilegedPermissionsRule : Rule {
    override val id = "APK-SEC-019"
    override val name = "High-Risk Sensitive Permissions Requested"
    override val description = "Application requests high-risk Android permissions that grant invasive device access and expand the potential blast radius."

    private val highRiskPermissions = mapOf(
        "android.permission.SYSTEM_ALERT_WINDOW" to "Allows overlaying screens (tapjacking/clickjacking risk)",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "Allows silent or prompted APK installation",
        "android.permission.READ_SMS" to "Allows reading incoming 2FA SMS tokens",
        "android.permission.RECEIVE_SMS" to "Allows intercepting incoming SMS messages",
        "android.permission.READ_CALL_LOG" to "Allows reading full call history and metadata",
        "android.permission.PROCESS_OUTGOING_CALLS" to "Allows intercepting or redirecting outgoing calls",
        "android.permission.RECORD_AUDIO" to "Allows microphone audio recording",
        "android.permission.ACCESS_BACKGROUND_LOCATION" to "Allows persistent background location tracking"
    )

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        for (req in context.attackSurface.requestedPermissions) {
            val riskDesc = highRiskPermissions[req.name]
            if (riskDesc != null) {
                findings.add(
                    Finding(
                        id = id,
                        title = "High-Risk Permission: ${req.name.substringAfterLast('.')}",
                        severity = Severity.MEDIUM,
                        confidence = Confidence.CERTAIN,
                        cwe = "CWE-250",
                        owasp = "M4: Insufficient Input/Output Validation",
                        description = "Application requests '${req.name}': $riskDesc.",
                        remediation = "Evaluate whether this sensitive permission is strictly necessary for core functionality. Remove if unused.",
                        component = null,
                        targetClass = null,
                        targetMethod = null,
                        evidence = "<uses-permission android:name=\"${req.name}\"/>",
                        lineOrOffset = null
                    )
                )
            }
        }
        return findings
    }
}
