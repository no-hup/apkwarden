package io.apkwarden.core.rules

import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import io.apkwarden.core.dex.MethodAnalyzer
import io.apkwarden.core.dex.RegisterValue
import io.apkwarden.core.dex.TaintSource
import io.apkwarden.core.model.Confidence
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.Reachability
import io.apkwarden.core.model.Severity

/**
 * APK-SEC-005: Dirty Stream Path Traversal
 * ContentProvider / openInputStream file write using Uri.getLastPathSegment() without canonicalization.
 */
class DirtyStreamTraversalRule : Rule {
    override val id = "APK-SEC-005"
    override val name = "Dirty Stream Path Traversal"
    override val description = "Application reads an incoming content stream via ContentResolver.openInputStream and writes to a destination file derived from Uri.getLastPathSegment() or displayName without canonical path validation, allowing file overwrite."
    override val targetSinks = setOf("openInputStream")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val openStreamCalls = context.dexIndex.findCallSites("android.content.ContentResolver", "openInputStream")

        for (cs in openStreamCalls) {
            val reachability = context.dexIndex.checkReachability(cs.callerClass, context.attackSurface)
            if (reachability == Reachability.UNREACHABLE) continue

            val analyzer = MethodAnalyzer(cs.method)
            val hasDisplayName = analyzer.containsStringLiteral { it == "_display_name" || it == "display_name" }
            val hasLastPathSegment = analyzer.containsCallTo("android.net.Uri", "getLastPathSegment") ||
                    analyzer.containsCallTo("android.net.Uri", "getPath") || hasDisplayName
            val hasSanitization = analyzer.hasPathSanitization()

            if (hasLastPathSegment && !hasSanitization) {
                val (title, severity, confidence, desc) = when (reachability) {
                    Reachability.DIRECT -> Quadruple(
                        "Dirty Stream File Overwrite Vulnerability",
                        Severity.CRITICAL,
                        Confidence.FIRM,
                        "Exported class '${cs.callerClass}#${cs.callerMethod}' reads from an external Content Uri and writes to local disk using an unvalidated path segment without canonical path validation."
                    )
                    Reachability.REACHABLE -> Quadruple(
                        "Dirty Stream File Overwrite Vulnerability via Reachable Component",
                        Severity.HIGH,
                        Confidence.FIRM,
                        "Component '${cs.callerClass}#${cs.callerMethod}' is reachable from an exported component and writes Content Uri data without canonical path validation."
                    )
                    Reachability.UNKNOWN -> Quadruple(
                        "Potential Dirty Stream File Overwrite (Indirect / Unknown Entry Point)",
                        Severity.MEDIUM,
                        Confidence.TENTATIVE,
                        "Class '${cs.callerClass}#${cs.callerMethod}' reads from a Content Uri and writes to local disk without canonical path validation. An entry point from an exported component was not statically resolved within 3 hops, but this may be reachable dynamically."
                    )
                    Reachability.UNREACHABLE -> continue
                }

                findings.add(
                    Finding(
                        id = id,
                        title = title,
                        severity = severity,
                        confidence = confidence,
                        cwe = "CWE-22",
                        owasp = "M1: Insecure Data Storage",
                        description = desc,
                        remediation = "Sanitize the filename to strip directory traversal sequences: `val name = File(uri.lastPathSegment).name; val target = File(outputDir, name); if (!target.canonicalPath.startsWith(outputDir.canonicalPath)) throw SecurityException();`",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = "Method calls openInputStream and Uri.getLastPathSegment() without File.getCanonicalPath()",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}",
                        reachability = reachability
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-006: Zip Slip Vulnerability
 * Extraction of zip archives without canonical destination check.
 */
class ZipSlipRule : Rule {
    override val id = "APK-SEC-006"
    override val name = "Zip Slip Path Traversal"
    override val description = "Unarchiving logic extracts zip entries using ZipEntry.getName() and writes to disk without verifying that the canonical destination path remains within the target extraction directory."
    override val targetSinks = setOf("getNextEntry")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val getNextEntryCalls = context.dexIndex.findCallSites("java.util.zip.ZipInputStream", "getNextEntry")

        for (cs in getNextEntryCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val hasGetEntryName = analyzer.containsCallTo("java.util.zip.ZipEntry", "getName")
            val hasFileWrite = analyzer.containsCallTo("java.io.File", "<init>") ||
                    analyzer.containsCallTo("java.io.FileOutputStream", "<init>")
            val hasSanitization = analyzer.hasPathSanitization()

            if (hasGetEntryName && hasFileWrite && !hasSanitization) {
                findings.add(
                    Finding(
                        id = id,
                        title = "Zip Slip Vulnerability in Archive Extraction",
                        severity = Severity.HIGH,
                        confidence = Confidence.FIRM,
                        cwe = "CWE-22",
                        owasp = "M1: Insecure Data Storage",
                        description = "Class '${cs.callerClass}#${cs.callerMethod}' extracts zip entries without verifying if canonical entry path escapes the destination folder.",
                        remediation = "Validate canonical file paths during zip extraction: `val destFile = File(destDir, entry.name); if (!destFile.canonicalPath.startsWith(destDir.canonicalPath + File.separator)) throw SecurityException(\"Zip Slip attempt\");`",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = "ZipInputStream.getNextEntry() and ZipEntry.getName() used without File.getCanonicalPath()",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-016: World Readable / Writable File
 * MODE_WORLD_READABLE (0x1) or MODE_WORLD_WRITEABLE (0x2)
 */
class WorldReadableWritableRule : Rule {
    override val id = "APK-SEC-016"
    override val name = "World Readable or Writable File Creation"
    override val description = "Application creates files or shared preferences using deprecated MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE flags, exposing local application storage to all other apps on device."
    override val targetSinks = setOf("openFileOutput", "getSharedPreferences")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val targetCalls = context.dexIndex.findCallSites("android.content.Context", "openFileOutput") +
                context.dexIndex.findCallSites("android.content.Context", "getSharedPreferences")

        val modeWorldReadable = 0x0001
        val modeWorldWritable = 0x0002

        for (cs in targetCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            // openFileOutput(name, mode) -> mode is arg 2
            // getSharedPreferences(name, mode) -> mode is arg 2
            if (args.size < 3) continue
            val modeReg = args[2]
            val regVal = analyzer.getRegisterValue(modeReg, cs.instructionIndex)

            var matched = false
            var modeName = ""

            if (regVal is RegisterValue.IntConstant) {
                val mode = regVal.value
                if (mode and modeWorldReadable != 0) {
                    matched = true
                    modeName = "MODE_WORLD_READABLE"
                } else if (mode and modeWorldWritable != 0) {
                    matched = true
                    modeName = "MODE_WORLD_WRITEABLE"
                }
            }

            if (matched) {
                findings.add(
                    Finding(
                        id = id,
                        title = "Insecure File Mode: $modeName",
                        severity = Severity.HIGH,
                        confidence = Confidence.CERTAIN,
                        cwe = "CWE-732",
                        owasp = "M1: Insecure Data Storage",
                        description = "Class '${cs.callerClass}#${cs.callerMethod}' calls '${cs.targetMethod}' with $modeName. This allows any other app installed on the device to read or write this file.",
                        remediation = "Use `Context.MODE_PRIVATE` (0) for all local files and shared preferences.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = "$modeName flag (0x${(regVal as RegisterValue.IntConstant).value.toString(16)}) passed to ${cs.targetMethod}",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-020: Sensitive Data in Plaintext SharedPreferences
 */
class InsecureSharedPrefsRule : Rule {
    override val id = "APK-SEC-020"
    override val name = "Sensitive Token in Unencrypted SharedPreferences"
    override val description = "Application stores authentication tokens, credentials, or secrets in unencrypted SharedPreferences instead of EncryptedSharedPreferences."
    override val targetSinks = setOf("putString")

    private val sensitiveKeywords = setOf("auth_token", "access_token", "jwt", "refresh_token", "password", "api_secret", "session_token")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val putStringCalls = context.dexIndex.findCallSites("android.content.SharedPreferences\$Editor", "putString")

        for (cs in putStringCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            // putString(key, val) -> key is arg 1
            if (args.size < 2) continue
            val keyReg = args[1]
            val regVal = analyzer.getRegisterValue(keyReg, cs.instructionIndex)

            if (regVal is RegisterValue.StringConstant) {
                val key = regVal.value.lowercase()
                if (sensitiveKeywords.any { key.contains(it) }) {
                    findings.add(
                        Finding(
                            id = id,
                            title = "Sensitive Key Stored in Plaintext SharedPreferences",
                            severity = Severity.LOW,
                            confidence = Confidence.FIRM,
                            cwe = "CWE-312",
                            owasp = "M1: Insecure Data Storage",
                            description = "Key '${regVal.value}' stored in standard unencrypted SharedPreferences in '${cs.callerClass}#${cs.callerMethod}'. Plaintext data is accessible in app backups and rooted devices.",
                            remediation = "Use AndroidX `EncryptedSharedPreferences.create()` backed by Android KeyStore.",
                            component = cs.callerClass,
                            targetClass = cs.callerClass,
                            targetMethod = cs.callerMethod,
                            evidence = "SharedPreferences.Editor.putString(\"${regVal.value}\", ...)",
                            lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                        )
                    )
                }
            }
        }
        return findings
    }
}
