package io.apkwarden.core.model

import kotlinx.serialization.Serializable

@Serializable
enum class Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
}

@Serializable
enum class Confidence {
    CERTAIN,
    FIRM,
    TENTATIVE
}

@Serializable
enum class Reachability {
    DIRECT,
    REACHABLE,
    UNKNOWN,
    UNREACHABLE
}

@Serializable
data class Finding(
    val id: String,
    val title: String,
    val severity: Severity,
    val confidence: Confidence,
    val cwe: String,
    val owasp: String,
    val description: String,
    val remediation: String,
    val component: String? = null,
    val targetClass: String? = null,
    val targetMethod: String? = null,
    val evidence: String? = null,
    val lineOrOffset: String? = null,
    val reachability: Reachability = Reachability.DIRECT,
    val codeSnippet: String? = null,
    val isSuppressed: Boolean = false
)

@Serializable
data class ScanSummary(
    val totalFindings: Int,
    val criticalCount: Int,
    val highCount: Int,
    val mediumCount: Int,
    val lowCount: Int,
    val infoCount: Int,
    val securityScore: Int
)

@Serializable
data class ScanReport(
    val apkName: String,
    val scanTimestamp: String,
    val attackSurface: AttackSurface,
    val stackFingerprint: StackFingerprint,
    val findings: List<Finding>,
    val summary: ScanSummary,
    val scanWarnings: List<String> = emptyList()
)
