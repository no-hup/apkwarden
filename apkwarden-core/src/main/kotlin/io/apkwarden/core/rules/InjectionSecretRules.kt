package io.apkwarden.core.rules

import com.android.tools.smali.dexlib2.Opcode
import io.apkwarden.core.dex.MethodAnalyzer
import io.apkwarden.core.dex.RegisterValue
import io.apkwarden.core.model.Confidence
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.Reachability
import io.apkwarden.core.model.Severity
import kotlin.math.ln

/**
 * APK-SEC-015: SQL Injection via rawQuery / execSQL
 */
class SqlInjectionRule : Rule {
    override val id = "APK-SEC-015"
    override val name = "SQL Injection in SQLite Query Execution"
    override val description = "Application constructs SQL query string using dynamic string concatenation before passing to SQLiteDatabase.rawQuery or execSQL instead of parameterized queries."
    override val targetSinks = setOf("rawQuery", "execSQL")

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val sqlCalls = context.dexIndex.findCallSites("android.database.sqlite.SQLiteDatabase", "rawQuery") +
                context.dexIndex.findCallSites("android.database.sqlite.SQLiteDatabase", "execSQL")

        for (cs in sqlCalls) {
            val reachability = context.dexIndex.checkReachability(cs.callerClass, context.attackSurface)
            val analyzer = MethodAnalyzer(cs.method)
            val descriptor = analyzer.getMethodDescriptor()
            val args = analyzer.getInvocationArgs(cs.instruction)
            val sqlReg = args.getOrNull(1)

            if (sqlReg != null) {
                val sqlVal = analyzer.getRegisterValue(sqlReg, cs.instructionIndex)
                if (sqlVal is RegisterValue.StringConstant) {
                    continue
                }

                // Trace back where sqlReg was defined
                var isBuilderToString = false
                var trackedReg = sqlReg
                for (k in (cs.instructionIndex - 1) downTo 0) {
                    val inst = cs.method.implementation?.instructions?.elementAtOrNull(k) ?: break
                    if (inst is com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction &&
                        (inst.opcode == Opcode.MOVE_RESULT || inst.opcode == Opcode.MOVE_RESULT_OBJECT) &&
                        inst.registerA == trackedReg
                    ) {
                        val callInst = if (k > 0) cs.method.implementation?.instructions?.elementAtOrNull(k - 1) else null
                        if (callInst is com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction) {
                            val mRef = callInst.reference as? com.android.tools.smali.dexlib2.iface.reference.MethodReference
                            if (mRef != null && mRef.name == "toString" && mRef.definingClass.contains("StringBuilder")) {
                                isBuilderToString = true
                            }
                        }
                        break
                    }
                    if (inst is com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction &&
                        (inst.opcode == Opcode.MOVE || inst.opcode == Opcode.MOVE_OBJECT ||
                         inst.opcode == Opcode.MOVE_16 || inst.opcode == Opcode.MOVE_OBJECT_16 ||
                         inst.opcode == Opcode.MOVE_FROM16 || inst.opcode == Opcode.MOVE_OBJECT_FROM16) &&
                        inst.registerA == trackedReg
                    ) {
                        trackedReg = inst.registerB
                        continue
                    }
                    if (inst.opcode.setsRegister() || inst.opcode.setsWideRegister()) {
                        val destReg = when (inst) {
                            is com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction -> inst.registerA
                            is com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction -> inst.registerA
                            is com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction -> inst.registerA
                            else -> null
                        }
                        if (destReg == trackedReg) {
                            break
                        }
                    }
                }

                if (isBuilderToString && analyzer.isAllStringBuilderAppendsConstant(cs.instructionIndex)) {
                    continue
                }
            }

            val hasStringBuilder = analyzer.containsCallTo("java.lang.StringBuilder", "append")
            val hasStringConcat = analyzer.containsCallTo("java.lang.String", "concat") ||
                    analyzer.containsCallTo("java.lang.String", "format")

            if (hasStringBuilder || hasStringConcat) {
                findings.add(
                    Finding(
                        id = id,
                        title = "Dynamic String Concatenation in ${cs.targetMethod}",
                        severity = Severity.HIGH,
                        confidence = Confidence.FIRM,
                        cwe = "CWE-89",
                        owasp = "M4: Insufficient Input/Output Validation",
                        description = "Class '${cs.callerClass}#${cs.callerMethod}' appears to construct a SQL command dynamically using StringBuilder/concatenation before calling SQLiteDatabase.${cs.targetMethod}. If untrusted inputs are included, this causes SQL Injection.",
                        remediation = "Use parameterized SQL queries with `?` placeholders and selection arguments: `db.rawQuery(\"SELECT * FROM users WHERE id = ?\", arrayOf(userId))`.",
                        component = cs.callerClass,
                        targetClass = cs.callerClass,
                        targetMethod = cs.callerMethod,
                        methodDescriptor = descriptor,
                        evidence = "Call to SQLiteDatabase.${cs.targetMethod} preceded by StringBuilder/String concatenation in ${cs.callerClass}",
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
 * APK-SEC-017: Hardcoded Secrets & High-Entropy Credentials
 */
class HardcodedSecretsRule : Rule {
    override val id = "APK-SEC-017"
    override val name = "Hardcoded Secret or API Key in Bytecode"
    override val description = "Application contains hardcoded cloud API keys, private keys, authentication tokens, or high-entropy credentials embedded directly in DEX strings."

    private data class KnownPattern(
        val regex: Regex,
        val secretType: String,
        val severity: Severity,
        val confidence: Confidence,
        val remediation: String
    )

    private val secretPatterns = listOf(
        KnownPattern(
            Regex("""AKIA[0-9A-Z]{16}"""),
            "AWS Access Key ID",
            Severity.HIGH,
            Confidence.CERTAIN,
            "Remove hardcoded AWS credentials from the APK. Use backend token exchange (Cognito/STS) with short-lived session credentials."
        ),
        KnownPattern(
            Regex("""AIza[0-9A-Za-z_\-]{35}"""),
            "Google API Key",
            Severity.MEDIUM,
            Confidence.FIRM,
            "Check Google API key restrictions in Google Cloud Console. Restrict the key by Android package name and SHA-1 certificate fingerprint to prevent unauthorized usage."
        ),
        KnownPattern(
            Regex("""sk_live_[0-9a-zA-Z]{24,32}"""),
            "Stripe Live Secret Key",
            Severity.CRITICAL,
            Confidence.CERTAIN,
            "IMMEDIATELY revoke this Stripe live secret key. Secret keys must only be used on your secure backend server."
        ),
        KnownPattern(
            Regex("""xox[baprs]-[0-9a-zA-Z]{10,48}"""),
            "Slack API Token",
            Severity.HIGH,
            Confidence.CERTAIN,
            "Revoke this Slack API token. Route all Slack workspace communications through an authenticated server endpoint."
        ),
        KnownPattern(
            Regex("""(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.{20,}"""),
            "PEM Encoded Private Key",
            Severity.CRITICAL,
            Confidence.CERTAIN,
            "Remove private cryptographic keys from client bytecode. Store keys in the Android Keystore hardware backed security module."
        ),
        KnownPattern(
            Regex("""sq0csp-[0-9A-Za-z_\-]{43}"""),
            "Square Access Token",
            Severity.HIGH,
            Confidence.CERTAIN,
            "Remove Square production access tokens from client APKs."
        ),
        KnownPattern(
            Regex("""^phc_[a-zA-Z0-9_\-]{32,64}$"""),
            "PostHog Project API Key",
            Severity.INFO,
            Confidence.CERTAIN,
            "Verify that this PostHog project key is restricted to write-only client ingest permissions in the PostHog project settings."
        ),
        KnownPattern(
            Regex("""https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+"""),
            "Sentry DSN",
            Severity.INFO,
            Confidence.CERTAIN,
            "Verify that this Sentry DSN endpoint is restricted to event capture and rate-limited in Sentry project settings."
        ),
        KnownPattern(
            Regex("""^pub[a-f0-9]{32}$"""),
            "Datadog Client Token",
            Severity.LOW,
            Confidence.TENTATIVE,
            "Verify that this Datadog client token is restricted to client telemetry intake."
        )
    )

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val seenTokens = mutableSetOf<String>()

        val stringOccurrences = context.dexIndex.findStringLiterals { str ->
            str.length >= 16 && !str.startsWith("Landroid/") && !str.startsWith("Landroidx/")
        }

        for (so in stringOccurrences) {
            val literal = so.string
            if (seenTokens.contains(literal)) continue

            // 1. Check known high-value regex patterns
            var matchedKnown = false
            for (pattern in secretPatterns) {
                if (pattern.regex.containsMatchIn(literal)) {
                    seenTokens.add(literal)
                    matchedKnown = true
                    val masked = maskSecret(literal)
                    findings.add(
                        Finding(
                            id = id,
                            title = "Hardcoded ${pattern.secretType} Detected",
                            severity = pattern.severity,
                            confidence = pattern.confidence,
                            cwe = "CWE-798",
                            owasp = "M1: Insecure Data Storage",
                            description = "Discovered ${pattern.secretType} ($masked) in '${so.callerClass}#${so.callerMethod}'.",
                            remediation = pattern.remediation,
                            component = so.callerClass,
                            targetClass = so.callerClass,
                            targetMethod = so.callerMethod,
                            evidence = "Matched pattern for ${pattern.secretType}: $masked",
                            lineOrOffset = "Instruction offset: ${so.instructionIndex}"
                        )
                    )
                    break
                }
            }
            if (matchedKnown) continue

            // 2. High-entropy token check for standalone strings
            if (!seenTokens.contains(literal) && literal.length in 28..80) {
                if (isPotentialGenericSecret(literal)) {
                    val entropy = calculateShannonEntropy(literal)
                    if (entropy > 4.5) {
                        seenTokens.add(literal)
                        val masked = maskSecret(literal)
                        findings.add(
                            Finding(
                                id = id,
                                title = "High-Entropy Secret or Token in Bytecode",
                                severity = Severity.MEDIUM,
                                confidence = Confidence.TENTATIVE,
                                cwe = "CWE-798",
                                owasp = "M1: Insecure Data Storage",
                                description = "Discovered high-entropy string ($masked, Shannon entropy=${"%.2f".format(entropy)}) in '${so.callerClass}#${so.callerMethod}'. This resembles an API secret or encryption key.",
                                remediation = "Verify if this string represents a secret token. If so, store it securely or obtain it dynamically via authenticated endpoints.",
                                component = so.callerClass,
                                targetClass = so.callerClass,
                                targetMethod = so.callerMethod,
                                evidence = "High entropy literal ($masked, entropy=${"%.2f".format(entropy)})",
                                lineOrOffset = "Instruction offset: ${so.instructionIndex}"
                            )
                        )
                    }
                }
            }
        }

        return findings
    }

    private fun isPotentialGenericSecret(s: String): Boolean {
        // Exclude common false positives: framework names anywhere in the string
        if (s.contains("android.permission.") || s.contains("android.intent.") ||
            s.contains("android.settings.") || s.contains("android.provider.")) return false
        if (s.startsWith("android.") || s.startsWith("androidx.") || s.startsWith("com.android.")) return false
        if (s.startsWith("kotlin.") || s.startsWith("java.")) return false
        if (s.contains("http://") || s.contains("https://") || s.contains('/') || s.contains('\\')) return false
        if (s.contains(".com") || s.contains(".org") || s.contains(".java") || s.contains(".kt")) return false
        if (s.matches(Regex("""[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"""))) return false // UUID
        if (s.matches(Regex("""[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}"""))) return false // Pure hex hash
        if (s.contains(' ') || s.contains('\t') || s.contains('\n')) return false

        // Dotted Java-style identifiers: >= 2 dots, each part valid identifier, no base64/URL chars
        // e.g. com.wispr.flowapp.service.ACTION_PERMISSION_GRANTED
        // EXCEPTION: Strings starting with "eyJ" (JWTs) are never rejected
        if (!s.startsWith("eyJ") && s.count { it == '.' } >= 2 && !s.contains('+') && !s.contains('=') && !s.contains('-')) {
            val parts = s.split('.')
            if (parts.all { it.matches(Regex("""^[A-Za-z_$][A-Za-z0-9_$]*$""")) }) {
                return false
            }
        }

        return true
    }

    private fun calculateShannonEntropy(s: String): Double {
        val frequencies = mutableMapOf<Char, Int>()
        for (c in s) {
            frequencies[c] = frequencies.getOrDefault(c, 0) + 1
        }
        val len = s.length.toDouble()
        var entropy = 0.0
        val log2 = ln(2.0)
        for (count in frequencies.values) {
            val p = count / len
            entropy -= p * (ln(p) / log2)
        }
        return entropy
    }

    private fun maskSecret(s: String): String {
        return if (s.length <= 8) "********"
        else s.take(4) + "..." + s.takeLast(4)
    }
}
