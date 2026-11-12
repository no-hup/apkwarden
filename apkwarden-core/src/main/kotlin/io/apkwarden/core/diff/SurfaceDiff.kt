package io.apkwarden.core.diff

import io.apkwarden.core.model.LockedComponent
import kotlinx.serialization.Serializable

@Serializable
enum class DiffSeverity {
    BREAKING,
    WARNING,
    INFO
}

@Serializable
data class DiffItem(
    val category: String, // "COMPONENT", "PERMISSION", "NETWORK", "SDK", "DEEP_LINK"
    val severity: DiffSeverity,
    val message: String,
    val detail: String? = null
)

@Serializable
data class SurfaceDiffResult(
    val basePackageName: String,
    val headPackageName: String,
    val hasBreakingChanges: Boolean,
    val totalChanges: Int,
    val breakingCount: Int,
    val warningCount: Int,
    val infoCount: Int,
    val addedExportedComponents: List<LockedComponent> = emptyList(),
    val removedExportedComponents: List<LockedComponent> = emptyList(),
    val addedPermissions: List<String> = emptyList(),
    val removedPermissions: List<String> = emptyList(),
    val diffItems: List<DiffItem> = emptyList()
)
