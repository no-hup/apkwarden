package io.apkwarden.core.sarif

import io.apkwarden.core.model.ScanReport
import io.apkwarden.core.model.Severity
import io.apkwarden.core.rules.RuleRegistry
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

object SarifSerializer {

    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
    }

    fun toSarif(report: ScanReport): SarifReport {
        // Collect distinct rules for the tool driver
        val ruleMap = RuleRegistry.allRules.associateBy { it.id }

        val sarifRules = report.findings.map { it.id }.distinct().mapNotNull { id ->
            val rule = ruleMap[id] ?: return@mapNotNull null
            val defaultLevel = when {
                id.startsWith("APK-SEC-001") || id.startsWith("APK-SEC-005") || id.startsWith("APK-SEC-011") || id.startsWith("APK-SEC-021") -> "error"
                else -> "warning"
            }
            SarifRule(
                id = rule.id,
                name = rule.name.replace(' ', '_'),
                shortDescription = SarifText(rule.name),
                fullDescription = SarifText(rule.description),
                defaultConfiguration = SarifConfiguration(level = defaultLevel),
                help = SarifHelp(
                    text = "See documentation at https://github.com/apkwarden/apkwarden",
                    markdown = "**Rule:** ${rule.name}\n\n${rule.description}"
                ),
                properties = SarifRuleProperties(
                    tags = listOf("security", "android", "sast"),
                    precision = "high"
                )
            )
        }

        val sarifResults = report.findings.filter { !it.isSuppressed }.map { finding ->
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
                properties = mapOf(
                    "confidence" to finding.confidence.name,
                    "reachability" to finding.reachability.name,
                    "cwe" to finding.cwe,
                    "owasp" to finding.owasp,
                    "remediation" to finding.remediation
                )
            )
        }

        val run = SarifRun(
            tool = SarifTool(
                driver = SarifDriver(
                    name = "APKWarden",
                    version = "1.0.0",
                    informationUri = "https://github.com/apkwarden/apkwarden",
                    rules = sarifRules
                )
            ),
            results = sarifResults
        )

        return SarifReport(runs = listOf(run))
    }

    fun serialize(report: ScanReport): String {
        return json.encodeToString(toSarif(report))
    }
}
