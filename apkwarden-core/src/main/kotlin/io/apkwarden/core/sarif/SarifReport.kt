package io.apkwarden.core.sarif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SarifReport(
    val `$schema`: String = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    val version: String = "2.1.0",
    val runs: List<SarifRun>
)

@Serializable
data class SarifRun(
    val tool: SarifTool,
    val results: List<SarifResult>,
    val invocations: List<SarifInvocation> = emptyList()
)

@Serializable
data class SarifInvocation(
    val executionSuccessful: Boolean = true
)

@Serializable
data class SarifTool(
    val driver: SarifDriver
)

@Serializable
data class SarifDriver(
    val name: String = "APKWarden",
    val version: String = "1.0.0",
    val informationUri: String = "https://github.com/no-hup/apkwarden",
    val rules: List<SarifRule>
)

@Serializable
data class SarifRule(
    val id: String,
    val name: String,
    val shortDescription: SarifText,
    val fullDescription: SarifText,
    val defaultConfiguration: SarifConfiguration,
    val help: SarifHelp,
    val properties: SarifRuleProperties? = null
)

@Serializable
data class SarifRuleProperties(
    val tags: List<String> = emptyList(),
    val precision: String = "high",
    @SerialName("security-severity")
    val securitySeverity: String? = null
)

@Serializable
data class SarifConfiguration(
    val level: String // "error", "warning", "note"
)

@Serializable
data class SarifHelp(
    val text: String,
    val markdown: String? = null
)

@Serializable
data class SarifText(
    val text: String
)

@Serializable
data class SarifSuppression(
    val kind: String = "external",
    val status: String = "accepted",
    val justification: String? = null
)

@Serializable
data class SarifResult(
    val ruleId: String,
    val level: String, // "error", "warning", "note"
    val message: SarifText,
    val locations: List<SarifLocation> = emptyList(),
    val partialFingerprints: Map<String, String> = emptyMap(),
    val suppressions: List<SarifSuppression> = emptyList(),
    val properties: Map<String, String> = emptyMap()
)

@Serializable
data class SarifLocation(
    val physicalLocation: SarifPhysicalLocation
)

@Serializable
data class SarifPhysicalLocation(
    val artifactLocation: SarifArtifactLocation,
    val region: SarifRegion? = null
)

@Serializable
data class SarifArtifactLocation(
    val uri: String
)

@Serializable
data class SarifRegion(
    val startLine: Int = 1,
    val snippet: SarifText? = null
)
