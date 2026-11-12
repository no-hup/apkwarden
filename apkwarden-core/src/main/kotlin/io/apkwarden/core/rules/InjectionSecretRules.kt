package io.apkwarden.core.rules

import io.apkwarden.core.dex.MethodAnalyzer
import io.apkwarden.core.dex.RegisterValue
import io.apkwarden.core.model.Confidence
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.Severity
import kotlin.math.ln

/**
 * APK-SEC-015: SQL Injection via rawQuery / execSQL
 */
class SqlInjectionRule : Rule {
    override val id = "APK-SEC-015"
    override val name = "SQL Injection in SQLite Query Execution"
    override val description = "Application constructs SQL query string using dynamic string concatenation before passing to SQLiteDatabase.rawQuery or execSQL instead of parameterized queries."

    override fun analyze(context: AnalysisContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val sqlCalls = context.dexIndex.findCallSites("android.database.sqlite.SQLiteDatabase", "rawQuery") +
                context.dexIndex.findCallSites("android.database.sqlite.SQLiteDatabase", "execSQL")

        for (cs in sqlCalls) {
            val analyzer = MethodAnalyzer(cs.method)
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
                        evidence = "Call to SQLiteDatabase.${cs.targetMethod} preceded by StringBuilder/String concatenation in ${cs.callerClass}",
                        lineOrOffset = "Instruction offset: ${cs.instructionIndex}"
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

    private val secretPatterns = listOf(
        Regex("""AKIA[0-9A-Z]{16}""") to "AWS Access Key ID",
        Regex("""AIza[0-9A-Za-z_\-]{35}""") to "Google API Key",
        Regex("""sk_live_[0-9a-zA-Z]{24,32}""") to "Stripe Live Secret Key",
        Regex("""xox[baprs]-[0-9a-zA-Z]{10,48}""") to "Slack API Token",
        Regex("""-----BEGIN [A-Z ]*PRIVATE KEY-----""") to "PEM Encoded Private Key",
        Regex("""sq0csp-[0-9A-Za-z_\-]{43}""") to "Square Access Token"
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
            for ((regex, secretType) in secretPatterns) {
                if (regex.containsMatchIn(literal)) {
                    seenTokens.add(literal)
                    val masked = maskSecret(literal)
                    findings.add(
                        Finding(
                            id = id,
                            title = "Hardcoded $secretType Detected",
                            severity = Severity.HIGH,
                            confidence = Confidence.CERTAIN,
                            cwe = "CWE-798",
                            owasp = "M1: Insecure Data Storage",
                            description = "Discovered hardcoded $secretType ($masked) in '${so.callerClass}#${so.callerMethod}'. Anyone with the APK can extract this credential.",
                            remediation = "Remove hardcoded credentials from the APK. Move API keys to a secure backend or use dynamic token exchange.",
                            component = so.callerClass,
                            targetClass = so.callerClass,
                            targetMethod = so.callerMethod,
                            evidence = "Matched pattern for $secretType: $masked",
                            lineOrOffset = "Instruction offset: ${so.instructionIndex}"
                        )
                    )
                    break
                }
            }

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
        // Exclude common false positives: URLs, package names, permissions, intents, file paths, UUIDs
        if (s.startsWith("android.permission.") || s.startsWith("android.intent.") || s.startsWith("com.android.")) return false
        if (s.startsWith("androidx.") || s.startsWith("kotlin.") || s.startsWith("java.")) return false
        if (s.contains("http://") || s.contains("https://") || s.contains('/') || s.contains('\\')) return false
        if (s.contains(".com") || s.contains(".org") || s.contains(".java") || s.contains(".kt")) return false
        if (s.matches(Regex("""[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"""))) return false // UUID
        if (s.matches(Regex("""[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}"""))) return false // Pure hex hash
        if (s.contains(' ') || s.contains('\t') || s.contains('\n')) return false
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
