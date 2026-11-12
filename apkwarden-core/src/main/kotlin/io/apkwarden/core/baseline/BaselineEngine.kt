package io.apkwarden.core.baseline

import io.apkwarden.core.model.Finding
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.time.Instant

object BaselineEngine {

    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    }

    fun applyBaseline(findings: List<Finding>, baseline: BaselineFile): List<Finding> {
        if (baseline.suppressions.isEmpty()) return findings

        val suppressionLookup = baseline.suppressions.groupBy { it.ruleId.uppercase() }

        return findings.map { finding ->
            val ruleSuppressions = suppressionLookup[finding.id.uppercase()] ?: emptyList()
            val findingTarget = getFindingTarget(finding)

            val matched = ruleSuppressions.firstOrNull { supp ->
                supp.target == "*" ||
                        supp.target.equals(findingTarget, ignoreCase = true) ||
                        findingTarget.startsWith("${supp.target}#", ignoreCase = true) ||
                        (supp.target.endsWith("#*") && findingTarget.startsWith(supp.target.removeSuffix("*"), ignoreCase = true))
            }

            if (matched != null) {
                finding.copy(isSuppressed = true)
            } else {
                finding
            }
        }
    }

    fun generateBaseline(findings: List<Finding>, defaultReason: String = "Grandfathered finding"): BaselineFile {
        val suppressions = findings.map { finding ->
            BaselineSuppression(
                ruleId = finding.id,
                target = getFindingTarget(finding),
                reason = defaultReason
            )
        }.distinctBy { "${it.ruleId}:${it.target}" }
            .sortedWith(compareBy({ it.ruleId }, { it.target }))

        return BaselineFile(
            schemaVersion = 1,
            generatedAt = Instant.now().toString(),
            suppressions = suppressions
        )
    }

    fun serialize(baseline: BaselineFile): String = json.encodeToString(baseline)

    fun deserialize(jsonStr: String): BaselineFile = json.decodeFromString(jsonStr)

    private fun getFindingTarget(finding: Finding): String {
        return when {
            finding.targetClass != null && finding.targetMethod != null -> "${finding.targetClass}#${finding.targetMethod}"
            finding.targetClass != null -> finding.targetClass
            finding.component != null -> finding.component
            else -> finding.id
        }
    }
}
