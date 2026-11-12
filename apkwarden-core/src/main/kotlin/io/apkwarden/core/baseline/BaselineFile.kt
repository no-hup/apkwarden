package io.apkwarden.core.baseline

import kotlinx.serialization.Serializable

@Serializable
data class BaselineSuppression(
    val ruleId: String,
    val target: String,
    val reason: String? = null,
    val expiresAt: String? = null
)

@Serializable
data class BaselineFile(
    val schemaVersion: Int = 1,
    val generatedAt: String,
    val suppressions: List<BaselineSuppression> = emptyList()
)
