package io.apkwarden.core.rules

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import io.apkwarden.core.dex.MethodAnalyzer
import io.apkwarden.core.dex.RegisterValue
import io.apkwarden.core.model.Confidence
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.Severity

/**
 * APK-SEC-011: Insecure Cryptographic Cipher / Weak Algorithm
 * AES/ECB mode, DES, DESede, or static hardcoded key
 */
class InsecureCryptoRule : Rule {
    override val id = "APK-SEC-011"
    override val name = "Insecure Cryptographic Cipher or Mode"
    override val description = "Application uses broken or weak cryptographic algorithms (DES, DESede) or insecure block cipher modes (AES/ECB) which do not provide semantic security."

    private val weakAlgorithms = listOf("DES", "DESede", "RC2", "RC4", "Blowfish", "PBEWithMD5AndDES")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val cipherCalls = context.dexIndex.findCallSites("javax.crypto.Cipher", "getInstance")

        for (cs in cipherCalls) {
            val analyzer = MethodAnalyzer(cs.method)
            val args = analyzer.getInvocationArgs(cs.instruction)
            // static Cipher.getInstance(transformation) -> arg 0 is transformation string
            if (args.isEmpty()) continue
            val transformReg = args[0]
            val regVal = analyzer.getRegisterValue(transformReg, cs.instructionIndex)

            var isWeak = false
            var reason = ""

            if (regVal is RegisterValue.StringConstant) {
                val str = regVal.value
                when {
                    str.equals("AES", ignoreCase = true) -> {
                        isWeak = true
                        reason = "Cipher.getInstance(\"AES\") defaults to AES/ECB mode without an initialization vector (IV)"
                    }
                    str.contains("ECB", ignoreCase = true) && !str.startsWith("RSA", ignoreCase = true) -> {
                        isWeak = true
                        reason = "ECB mode ($str) does not hide data patterns and is vulnerable to block replay attacks"
                    }
                    weakAlgorithms.any { str.startsWith(it, ignoreCase = true) } -> {
                        isWeak = true
                        reason = "Weak or broken algorithm ($str) can be cracked with modern computational power"
                    }
                }
            }

            if (isWeak) {
                findings.add(
                    Finding(
                        id = id,
                        title = "Insecure Cipher Configuration",
                        severity = Severity.HIGH,
                        confidence = Confidence.CERTAIN,
                        cwe = "CWE-327",
                        owasp = "M2: Insecure Communication",
                        description = "Class '${cs.callerClass}#${cs.callerMethod}' initializes Cipher with an insecure transformation: $reason.",
                        remediation = "Use AES-GCM for authenticated encryption: `Cipher.getInstance(\"AES/GCM/NoPadding\")`.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = reason,
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-012: Insecure Pseudo-Random Number Generator
 * java.util.Random used instead of java.security.SecureRandom
 */
class InsecureRandomRule : Rule {
    override val id = "APK-SEC-012"
    override val name = "Insecure Random Generator (java.util.Random)"
    override val description = "java.util.Random produces statistically predictable pseudo-random sequences and must not be used for cryptographic operations, token generation, or security nonces."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val randomInitCalls = context.dexIndex.findCallSites("java.util.Random", "<init>")

        for (cs in randomInitCalls) {
            val caller = cs.callerClass.lowercase()
            // Check if caller class or method name implies security context
            val isSecurityContext = caller.contains("crypto") || caller.contains("auth") ||
                    caller.contains("token") || caller.contains("otp") || caller.contains("nonce") ||
                    caller.contains("session") || caller.contains("password") || caller.contains("security") ||
                    cs.callerMethod.lowercase().contains("token") || cs.callerMethod.lowercase().contains("key")

            if (isSecurityContext) {
                findings.add(
                    Finding(
                        id = id,
                        title = "java.util.Random Used in Security Context",
                        severity = Severity.MEDIUM,
                        confidence = Confidence.FIRM,
                        cwe = "CWE-330",
                        owasp = "M2: Insecure Communication",
                        description = "Class '${cs.callerClass}#${cs.callerMethod}' instantiates java.util.Random in a security-sensitive context. Pseudo-random numbers generated this way can be predicted by attackers.",
                        remediation = "Replace java.util.Random with cryptographically strong `java.security.SecureRandom`.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = "new java.util.Random() in ${cs.callerClass}",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}

/**
 * APK-SEC-013: Insecure Custom X509TrustManager
 * Empty checkServerTrusted implementation
 */
class InsecureTrustManagerRule : Rule {
    override val id = "APK-SEC-013"
    override val name = "Insecure Custom X509TrustManager (SSL Bypass)"
    override val description = "Application defines a custom X509TrustManager that fails to validate the server certificate chain (empty or non-throwing checkServerTrusted), disabling TLS/SSL security."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()

        for ((className, classDef) in context.dexIndex.classDefs) {
            val isTrustManager = context.dexIndex.hierarchy.isSubclassOf(className, "javax.net.ssl.X509TrustManager") ||
                    context.dexIndex.hierarchy.isSubclassOf(className, "javax.net.ssl.X509ExtendedTrustManager")
            if (isTrustManager) {
                for (method in classDef.methods) {
                    if (method.name == "checkServerTrusted") {
                        val impl = method.implementation ?: continue
                        val instructions = impl.instructions.toList()

                        // If the method delegates to another TrustManager, suppress
                        val delegates = instructions.any { inst ->
                            if (inst is ReferenceInstruction) {
                                (inst.reference as? MethodReference)?.name == "checkServerTrusted"
                            } else false
                        }
                        if (delegates) continue

                        // If empty method (e.g. only return-void, 1 instruction), or no throw / validation
                        val hasThrow = instructions.any { it.opcode == Opcode.THROW }
                        val isTrivialReturn = instructions.size <= 2 && instructions.any { it.opcode == Opcode.RETURN_VOID }

                        if (isTrivialReturn || !hasThrow) {
                            findings.add(
                                Finding(
                                    id = id,
                                    title = "TLS Certificate Validation Bypassed in X509TrustManager",
                                    severity = Severity.CRITICAL,
                                    confidence = Confidence.CERTAIN,
                                    cwe = "CWE-295",
                                    owasp = "M2: Insecure Communication",
                                    description = "Class '$className' implements X509TrustManager but its checkServerTrusted method contains no certificate verification logic or exception throwing. This permits full Man-in-the-Middle (MitM) attacks.",
                                    remediation = "Delete custom TrustManagers and use Android's default platform TrustManager along with res/xml/network_security_config.xml.",
                                    component = className,
                                    targetClass = className,
                                    targetMethod = method.name,
                                    evidence = "checkServerTrusted in $className has ${instructions.size} instructions and throws no CertificateException",
                                    lineOrOffset = null
                                )
                            )
                        }
                    }
                }
            }
        }
        return findings
    }
}

/**
 * APK-SEC-014: Allow All Hostname Verifier
 * Returns true unconditionally
 */
class AllowAllHostnameVerifierRule : Rule {
    override val id = "APK-SEC-014"
    override val name = "AllowAll HostnameVerifier (MitM Vulnerability)"
    override val description = "Application disables TLS hostname verification by using ALLOW_ALL_HOSTNAME_VERIFIER or a custom HostnameVerifier that always returns true."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()

        // Check for ALLOW_ALL_HOSTNAME_VERIFIER field access
        val allowAllAccess = context.dexIndex.findFieldAccesses("org.apache.http.conn.ssl.SSLSocketFactory", "ALLOW_ALL_HOSTNAME_VERIFIER")
        for (fa in allowAllAccess) {
            findings.add(
                Finding(
                    id = id,
                    title = "ALLOW_ALL_HOSTNAME_VERIFIER Used",
                    severity = Severity.CRITICAL,
                    confidence = Confidence.CERTAIN,
                    cwe = "CWE-295",
                    owasp = "M2: Insecure Communication",
                    description = "Class '${fa.callerClass}#${fa.callerMethod}' uses ALLOW_ALL_HOSTNAME_VERIFIER, allowing any valid TLS certificate to impersonate the target server.",
                    remediation = "Use standard hostname verification: `HttpsURLConnection.getDefaultHostnameVerifier()`.",
                    component = fa.callerClass,
                    targetClass = fa.callerClass,
                    targetMethod = fa.callerMethod,
                    evidence = "Reference to SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER",
                    lineOrOffset = "Instruction offset: ${fa.instructionIndex}"
                )
            )
        }

        // Check custom HostnameVerifier classes
        for ((className, classDef) in context.dexIndex.classDefs) {
            if (context.dexIndex.hierarchy.isSubclassOf(className, "javax.net.ssl.HostnameVerifier")) {
                for (method in classDef.methods) {
                    if (method.name == "verify") {
                        val impl = method.implementation ?: continue
                        val instructions = impl.instructions.toList()

                        // Look for: const/4 vA, #1; return vA
                        var returnsTrue = false
                        for (i in instructions.indices) {
                            val inst = instructions[i]
                            if (inst is com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction && inst.narrowLiteral == 1) {
                                if (i + 1 < instructions.size && instructions[i + 1].opcode == Opcode.RETURN) {
                                    returnsTrue = true
                                    break
                                }
                            }
                        }

                        if (returnsTrue && instructions.size <= 4) {
                            findings.add(
                                Finding(
                                    id = id,
                                    title = "Custom HostnameVerifier Accepts All Hostnames",
                                    severity = Severity.CRITICAL,
                                    confidence = Confidence.CERTAIN,
                                    cwe = "CWE-295",
                                    owasp = "M2: Insecure Communication",
                                    description = "Class '$className' implements HostnameVerifier.verify() which unconditionally returns true without checking the hostname against the peer certificate.",
                                    remediation = "Remove custom HostnameVerifier and rely on Android's built-in platform verifier.",
                                    component = className,
                                    targetClass = className,
                                    targetMethod = method.name,
                                    evidence = "HostnameVerifier.verify in $className returns true unconditionally",
                                    lineOrOffset = null
                                )
                            )
                        }
                    }
                }
            }
        }

        return findings
    }
}

/**
 * APK-SEC-018: Cleartext Traffic Permitted & HTTP Endpoints
 */
class CleartextTrafficRule : Rule {
    override val id = "APK-SEC-018"
    override val name = "Insecure Cleartext HTTP Communication"
    override val description = "Application contains plaintext http:// endpoints while network security configuration or manifest settings permit cleartext traffic."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val netConfig = context.attackSurface.networkSecurityConfig

        // Only flag if cleartext traffic is permitted via NSC, manifest, or targetSdk < 28
        val permitsCleartext = (context.attackSurface.usesCleartextTraffic == true) ||
                (netConfig?.baseCleartextPermitted ?: (context.attackSurface.targetSdk < 28))
        if (!permitsCleartext) return emptyList()

        val httpLiterals = context.dexIndex.findStringLiterals { str ->
            str.startsWith("http://") &&
                    !str.contains("localhost") &&
                    !str.contains("127.0.0.1") &&
                    !str.contains("schemas.android.com") &&
                    !str.contains("w3.org") &&
                    !str.contains("apache.org")
        }

        // Group by URL to avoid spamming findings
        val distinctUrls = httpLiterals.groupBy { it.string }

        for ((url, occurrences) in distinctUrls.entries.take(10)) {
            val firstOcc = occurrences.first()
            findings.add(
                Finding(
                    id = id,
                    title = "Cleartext HTTP URL in Application Bytecode",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.FIRM,
                    cwe = "CWE-319",
                    owasp = "M2: Insecure Communication",
                    description = "Cleartext URL '$url' is queried in '${firstOcc.callerClass}#${firstOcc.callerMethod}' while cleartext traffic is permitted (targetSdk=${context.attackSurface.targetSdk}). Plaintext HTTP exposes credentials and traffic to eavesdropping.",
                    remediation = "Migrate all HTTP endpoints to HTTPS and ensure `android:usesCleartextTraffic=\"false\"` is set.",
                    component = firstOcc.callerClass,
                    targetClass = firstOcc.callerClass,
                    targetMethod = firstOcc.callerMethod,
                    evidence = "Hardcoded HTTP string: $url (${occurrences.size} occurrences)",
                    lineOrOffset = null
                )
            )
        }

        return findings
    }
}

/**
 * APK-SEC-021: WebView SSL Error Ignored (SslErrorHandler.proceed)
 */
class WebViewSslBypassRule : Rule {
    override val id = "APK-SEC-021"
    override val name = "WebView SSL Error Bypassed (handler.proceed)"
    override val description = "Application's WebViewClient overrides onReceivedSslError and calls handler.proceed(), ignoring TLS/SSL certificate validation errors and enabling Man-in-the-Middle attacks."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val proceedCalls = context.dexIndex.findCallSites("android.webkit.SslErrorHandler", "proceed")

        for (cs in proceedCalls) {
            if (cs.callerMethod == "onReceivedSslError") {
                findings.add(
                    Finding(
                        id = id,
                        title = "SSL Certificate Validation Bypassed in WebViewClient",
                        severity = Severity.CRITICAL,
                        confidence = Confidence.CERTAIN,
                        cwe = "CWE-295",
                        owasp = "M2: Insecure Communication",
                        description = "Class '${cs.callerClass}#${cs.callerMethod}' unconditionally proceeds past SSL certificate errors by invoking SslErrorHandler.proceed(). Any attacker on the local network can intercept and manipulate WebView traffic.",
                        remediation = "Call `handler.cancel()` in onReceivedSslError. Never call `handler.proceed()` in production code.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        evidence = "Call to SslErrorHandler.proceed() in onReceivedSslError",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
                    )
                )
            }
        }
        return findings
    }
}
