package io.apkwarden.core.model

import kotlinx.serialization.Serializable

@Serializable
enum class ComponentType {
    ACTIVITY,
    SERVICE,
    RECEIVER,
    PROVIDER,
    ACTIVITY_ALIAS
}

@Serializable
enum class ProtectionLevel {
    NORMAL,
    DANGEROUS,
    SIGNATURE,
    SIGNATURE_OR_SYSTEM,
    INTERNAL,
    UNKNOWN
}

@Serializable
data class DeclaredPermission(
    val name: String,
    val protectionLevel: ProtectionLevel = ProtectionLevel.NORMAL,
    val rawProtectionLevel: String? = null
)

@Serializable
data class RequestedPermission(
    val name: String,
    val maxSdkVersion: Int? = null,
    val usesPermissionFlags: Int = 0
)

@Serializable
data class DeepLink(
    val scheme: String,
    val host: String? = null,
    val port: Int? = null,
    val path: String? = null,
    val pathPrefix: String? = null,
    val pathPattern: String? = null,
    val mimeType: String? = null,
    val autoVerify: Boolean = false,
    val targetComponent: String
)

@Serializable
data class IntentFilter(
    val actions: List<String> = emptyList(),
    val categories: List<String> = emptyList(),
    val dataSchemes: List<String> = emptyList(),
    val dataHosts: List<String> = emptyList(),
    val dataPaths: List<String> = emptyList(),
    val dataMimeTypes: List<String> = emptyList(),
    val priority: Int = 0,
    val autoVerify: Boolean = false
)

@Serializable
enum class ExportStatus {
    EXPLICIT_EXPORTED,
    IMPLICIT_EXPORTED,
    EXPORTED_ON_LEGACY_ONLY,
    NOT_EXPORTED
}

@Serializable
data class Component(
    val type: ComponentType,
    val name: String,
    val exported: Boolean,
    val exportStatus: ExportStatus = if (exported) ExportStatus.EXPLICIT_EXPORTED else ExportStatus.NOT_EXPORTED,
    val permission: String? = null,
    val readPermission: String? = null,
    val writePermission: String? = null,
    val intentFilters: List<IntentFilter> = emptyList(),
    val targetActivity: String? = null, // for activity-alias
    val grantUriPermissions: Boolean = false,
    val authorities: List<String> = emptyList(),
    val metadata: Map<String, String> = emptyMap(),
    val sourcePackage: String? = null // for first-party vs third-party SDK separation
)

@Serializable
data class FileProviderPath(
    val tag: String, // root-path, files-path, cache-path, external-path, etc.
    val name: String,
    val path: String,
    val isRootPath: Boolean = false,
    val isBroadWildcard: Boolean = false
)

@Serializable
data class NetworkDomainConfig(
    val domain: String,
    val includeSubdomains: Boolean = false,
    val cleartextPermitted: Boolean = false,
    val certificatePins: List<String> = emptyList(),
    val trustUserCerts: Boolean = false
)

@Serializable
data class NetworkSecurityConfig(
    val baseCleartextPermitted: Boolean = true,
    val domainConfigs: List<NetworkDomainConfig> = emptyList(),
    val trustUserCertsGlobally: Boolean = false
)

@Serializable
data class AttackSurface(
    val packageName: String,
    val versionCode: Long,
    val versionName: String?,
    val minSdk: Int,
    val targetSdk: Int,
    val compileSdk: Int?,
    val isDebuggable: Boolean,
    val isTestOnly: Boolean,
    val allowBackup: Boolean,
    val dataExtractionRulesDefined: Boolean,
    val requestedPermissions: List<RequestedPermission> = emptyList(),
    val declaredPermissions: List<DeclaredPermission> = emptyList(),
    val components: List<Component> = emptyList(),
    val deepLinks: List<DeepLink> = emptyList(),
    val fileProviderPaths: List<FileProviderPath> = emptyList(),
    val networkSecurityConfig: NetworkSecurityConfig? = null,
    val usesCleartextTraffic: Boolean? = null,
    val applicationClass: String? = null
) {
    val exportedComponents: List<Component>
        get() = components.filter { it.exported }

    val internalComponents: List<Component>
        get() = components.filter { !it.exported }
}
