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
    override val targetSinks = setOf("getInstance")

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
    override val targetSinks = setOf("<init>")

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
                        val descriptor = "(${method.parameters.joinToString("") { it.type }})${method.returnType}"

                        fun canThrowOrValidate(m: com.android.tools.smali.dexlib2.iface.Method, depth: Int, visited: MutableSet<String>): Boolean {
                            val mImpl = m.implementation ?: return false
                            val sig = "${m.definingClass}#${m.name}(${m.parameters.joinToString("") { it.type }})"
                            if (!visited.add(sig)) return false

                            for (inst in mImpl.instructions) {
                                if (inst.opcode == Opcode.THROW) return true
                                if (inst is ReferenceInstruction) {
                                    val mRef = inst.reference as? MethodReference ?: continue
                                    if (mRef.name == "checkServerTrusted" || mRef.name == "checkClientTrusted") return true
                                    if (depth < 2 && mRef.definingClass == m.definingClass) {
                                        val targetMethod = classDef.methods.firstOrNull {
                                            it.name == mRef.name && it.parameters.map { p -> p.type } == mRef.parameterTypes
                                        }
                                        if (targetMethod != null && canThrowOrValidate(targetMethod, depth + 1, visited)) {
                                            return true
                                        }
                                    }
                                }
                            }
                            return false
                        }

                        val visited = mutableSetOf<String>()
                        val isSafe = canThrowOrValidate(method, 0, visited)

                        if (!isSafe) {
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
                                    methodDescriptor = descriptor,
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

    private val skipHosts = setOf(
        "localhost", "127.0.0.1", "example.com", "www.example.com",
        "schemas.android.com", "w3.org", "www.w3.org", "apache.org",
        "ns.adobe.com", "purl.org"
    )

    private fun extractHost(url: String): String? {
        val withoutScheme = url.removePrefix("http://")
        val hostPart = withoutScheme.substringBefore('/').substringBefore(':').substringBefore('?')
        return hostPart.lowercase().takeIf { it.isNotEmpty() }
    }

    private fun isSkippedHost(host: String): Boolean {
        if (host in skipHosts) return true
        return skipHosts.any { host.endsWith(".$it") }
    }

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val netConfig = context.attackSurface.networkSecurityConfig

        // Only flag if cleartext traffic is permitted via NSC, manifest, or targetSdk < 28
        val permitsCleartext = (context.attackSurface.usesCleartextTraffic == true) ||
                (netConfig?.baseCleartextPermitted ?: (context.attackSurface.targetSdk < 28))
        if (!permitsCleartext) return emptyList()

        // If manifest explicitly sets usesCleartextTraffic="true" or NSC base config permits cleartext,
        // emit one dedicated finding for the configuration flag.
        if (context.attackSurface.usesCleartextTraffic == true || netConfig?.baseCleartextPermitted == true) {
            val configEvidence = if (context.attackSurface.usesCleartextTraffic == true) {
                "Manifest android:usesCleartextTraffic=\"true\" explicitly set"
            } else {
                "Network Security Config base-config allows cleartext traffic"
            }
            findings.add(
                Finding(
                    id = id,
                    title = "Cleartext HTTP Traffic Permitted by Configuration",
                    severity = Severity.HIGH,
                    confidence = Confidence.CERTAIN,
                    cwe = "CWE-319",
                    owasp = "M2: Insecure Communication",
                    description = "Application configuration ($configEvidence) explicitly permits unencrypted cleartext HTTP communication on targetSdk ${context.attackSurface.targetSdk}.",
                    remediation = "Disable cleartext HTTP traffic in AndroidManifest.xml (`android:usesCleartextTraffic=\"false\"`) and enforce HTTPS in network_security_config.xml.",
                    component = context.attackSurface.packageName,
                    targetClass = context.attackSurface.packageName,
                    targetMethod = null,
                    evidence = configEvidence,
                    lineOrOffset = null
                )
            )
        }

        val httpLiterals = context.dexIndex.findStringLiterals { str ->
            if (!str.startsWith("http://")) return@findStringLiterals false
            if (str.startsWith("http://javax.xml.XMLConstants/")) return@findStringLiterals false
            val host = extractHost(str) ?: return@findStringLiterals false
            !isSkippedHost(host)
        }

        // Group by host rather than full URL to avoid URL spam and prevent endpoint crowding
        val hostGroups = httpLiterals.groupBy { extractHost(it.string) ?: "unknown" }

        for ((host, occurrences) in hostGroups) {
            val firstOcc = occurrences.first()
            val exampleUrls = occurrences.map { it.string }.distinct().take(3).joinToString(", ")
            findings.add(
                Finding(
                    id = id,
                    title = "Cleartext HTTP Host in Application Bytecode",
                    severity = Severity.MEDIUM,
                    confidence = Confidence.FIRM,
                    cwe = "CWE-319",
                    owasp = "M2: Insecure Communication",
                    description = "Cleartext HTTP host '$host' is queried in '${firstOcc.callerClass}#${firstOcc.callerMethod}' while cleartext traffic is permitted (targetSdk=${context.attackSurface.targetSdk}). Plaintext HTTP exposes traffic to eavesdropping.",
                    remediation = "Migrate all HTTP endpoints on '$host' to HTTPS and ensure `android:usesCleartextTraffic=\"false\"` is set.",
                    component = firstOcc.callerClass,
                    targetClass = firstOcc.callerClass,
                    targetMethod = firstOcc.callerMethod,
                    evidence = "Hardcoded cleartext host '$host' (${occurrences.size} occurrences). Examples: $exampleUrls",
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
    override val targetSinks = setOf("proceed")

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
