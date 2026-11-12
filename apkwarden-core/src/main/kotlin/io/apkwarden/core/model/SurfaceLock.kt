package io.apkwarden.core.model

import kotlinx.serialization.Serializable

@Serializable
data class LockedComponent(
    val type: String,
    val name: String,
    val exported: Boolean,
    val permission: String? = null,
    val readPermission: String? = null,
    val writePermission: String? = null,
    val authorities: List<String> = emptyList(),
    val deepLinks: List<String> = emptyList()
)

@Serializable
data class LockedNetworkConfig(
    val baseCleartextPermitted: Boolean,
    val cleartextDomains: List<String> = emptyList(),
    val pinnedDomains: List<String> = emptyList(),
    val trustsUserCerts: Boolean
)

@Serializable
data class SurfaceLock(
    val schemaVersion: Int = 1,
    val packageName: String,
    val minSdk: Int,
    val targetSdk: Int,
    val requestedPermissions: List<String> = emptyList(),
    val declaredPermissions: List<String> = emptyList(),
    val exportedComponents: List<LockedComponent> = emptyList(),
    val deepLinks: List<String> = emptyList(),
    val nativeLibraries: List<String> = emptyList(),
    val networkSecurity: LockedNetworkConfig? = null,
    val sha256Fingerprint: String
)
