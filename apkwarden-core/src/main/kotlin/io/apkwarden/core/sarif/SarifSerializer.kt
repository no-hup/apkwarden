package io.apkwarden.core.sarif

import io.apkwarden.core.model.ScanReport
import io.apkwarden.core.model.Severity
import io.apkwarden.core.rules.RuleRegistry
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.MessageDigest

object SarifSerializer {

    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
    }

    fun toSarif(report: ScanReport): SarifReport {
        val ruleMap = RuleRegistry.allRules.associateBy { it.id }

        val sarifRules = report.findings.map { it.id }.distinct().mapNotNull { id ->
            val rule = ruleMap[id] ?: return@mapNotNull null
            // Look up highest severity from matching findings in this report
            val maxSeverity = report.findings.filter { it.id == id }.maxOfOrNull { it.severity } ?: Severity.MEDIUM
            val defaultLevel = when (maxSeverity) {
                Severity.CRITICAL, Severity.HIGH -> "error"
                Severity.MEDIUM -> "warning"
                Severity.LOW, Severity.INFO -> "note"
            }
            val securitySeverity = when (maxSeverity) {
                Severity.CRITICAL -> "9.0"
                Severity.HIGH -> "8.0"
                Severity.MEDIUM -> "5.0"
                Severity.LOW -> "2.0"
                Severity.INFO -> "1.0"
            }

            SarifRule(
                id = rule.id,
                name = rule.name.replace(' ', '_'),
                shortDescription = SarifText(rule.name),
                fullDescription = SarifText(rule.description),
                defaultConfiguration = SarifConfiguration(level = defaultLevel),
                help = SarifHelp(
                    text = "See documentation at https://github.com/no-hup/apkwarden",
                    markdown = "**Rule:** ${rule.name}\n\n${rule.description}"
                ),
                properties = SarifRuleProperties(
                    tags = listOf("security", "android", "sast"),
                    precision = "high",
                    securitySeverity = securitySeverity
                )
            )
        }

        val sarifResults = report.findings.map { finding ->
            val level = when (finding.severity) {
                Severity.CRITICAL, Severity.HIGH -> "error"
                Severity.MEDIUM -> "warning"
                Severity.LOW, Severity.INFO -> "note"
            }

            val targetFileUri = finding.targetClass?.let { cls ->
                cls.replace('.', '/') + ".smali"
            } ?: "AndroidManifest.xml"

            val region = if (finding.codeSnippet != null || finding.evidence != null) {
                SarifRegion(
                    startLine = 1,
                    snippet = SarifText(finding.codeSnippet ?: finding.evidence ?: "")
                )
            } else null

            // Stable logical fingerprint to prevent GitHub alert churn on line shift / rebuilds
            val fingerprintRaw = "${finding.id}:${finding.targetClass ?: ""}:${finding.targetMethod ?: ""}:${finding.methodDescriptor ?: ""}"
            val fingerprintHash = MessageDigest.getInstance("SHA-256")
                .digest(fingerprintRaw.toByteArray(Charsets.UTF_8))
                .take(8)
                .joinToString("") { "%02x".format(it) }

            val suppressions = if (finding.isSuppressed) {
                listOf(
                    SarifSuppression(
                        kind = "external",
                        status = "accepted",
                        justification = "Grandfathered baseline suppression"
                    )
                )
            } else emptyList()

            SarifResult(
                ruleId = finding.id,
                level = level,
                message = SarifText("${finding.title}: ${finding.description}"),
                locations = listOf(
                    SarifLocation(
                        physicalLocation = SarifPhysicalLocation(
                            artifactLocation = SarifArtifactLocation(uri = targetFileUri),
                            region = region
                        )
                    )
                ),
                partialFingerprints = mapOf(
                    "logicalFingerprint/v1" to fingerprintHash
                ),
                suppressions = suppressions,
                properties = buildMap {
                    put("confidence", finding.confidence.name)
                    put("reachability", finding.reachability.name)
                    put("owner", finding.owner.name)
                    if (finding.methodDescriptor != null) {
                        put("methodDescriptor", finding.methodDescriptor!!)
                    }
                    put("cwe", finding.cwe)
                    put("owasp", finding.owasp)
                    put("remediation", finding.remediation)
                }
            )
        }

        val isExecutionSuccessful = report.scanWarnings.none {
            it.contains("Failed to parse") || it.contains("PACKER DETECTED")
        }

        val run = SarifRun(
            tool = SarifTool(
                driver = SarifDriver(
                    name = "APKWarden",
                    version = "0.1.0",
                    informationUri = "https://github.com/no-hup/apkwarden",
                    rules = sarifRules
                )
            ),
            results = sarifResults,
            invocations = listOf(
                SarifInvocation(executionSuccessful = isExecutionSuccessful)
            )
        )

        return SarifReport(runs = listOf(run))
    }

    fun serialize(report: ScanReport): String {
        return json.encodeToString(toSarif(report))
    }
}
