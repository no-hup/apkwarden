package io.apkwarden.core.lock

import io.apkwarden.core.model.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.MessageDigest

@OptIn(ExperimentalSerializationApi::class)
object SurfaceLockGenerator {

    private val json = Json {
        prettyPrint = true
        prettyPrintIndent = "  "
        encodeDefaults = true
    }

    fun generate(surface: AttackSurface, fingerprint: StackFingerprint? = null): SurfaceLock {
        val sortedRequestedPerms = surface.requestedPermissions.map { it.name }.distinct().sorted()
        val sortedDeclaredPerms = surface.declaredPermissions.map { "${it.name}:${it.protectionLevel}" }.distinct().sorted()

        val lockedComponents = surface.exportedComponents.map { comp ->
            val compDeepLinks = surface.deepLinks
                .filter { it.targetComponent == comp.name }
                .map { formatDeepLink(it) }
                .distinct()
                .sorted()

            LockedComponent(
                type = comp.type.name,
                name = comp.name,
                exported = comp.exported,
                permission = comp.permission,
                readPermission = comp.readPermission,
                writePermission = comp.writePermission,
                authorities = comp.authorities.sorted(),
                deepLinks = compDeepLinks
            )
        }.sortedWith(compareBy({ it.type }, { it.name }))

        val allDeepLinks = surface.deepLinks.map { formatDeepLink(it) }.distinct().sorted()

        val nativeLibs = fingerprint?.nativeLibraries
            ?.map { "${it.name} (${it.abi})" }
            ?.distinct()
            ?.sorted()
            ?: emptyList()

        val lockedNetwork = surface.networkSecurityConfig?.let { nsc ->
            LockedNetworkConfig(
                baseCleartextPermitted = nsc.baseCleartextPermitted,
                cleartextDomains = nsc.domainConfigs.filter { it.cleartextPermitted }.map { it.domain }.sorted(),
                pinnedDomains = nsc.domainConfigs.filter { it.certificatePins.isNotEmpty() }.map { it.domain }.sorted(),
                trustsUserCerts = nsc.trustUserCertsGlobally || nsc.domainConfigs.any { it.trustUserCerts }
            )
        }

        // Generate SHA-256 fingerprint over the canonical content
        val rawDataToHash = buildString {
            append(surface.packageName).append(";")
            append(surface.minSdk).append(";").append(surface.targetSdk).append(";")
            append(sortedRequestedPerms.joinToString(",")).append(";")
            append(lockedComponents.joinToString(",") { "${it.type}:${it.name}:${it.permission}" }).append(";")
            append(allDeepLinks.joinToString(","))
        }

        val digest = MessageDigest.getInstance("SHA-256")
        val sha256 = digest.digest(rawDataToHash.toByteArray(Charsets.UTF_8)).joinToString("") {
            "%02x".format(it)
        }

        return SurfaceLock(
            schemaVersion = 1,
            packageName = surface.packageName,
            minSdk = surface.minSdk,
            targetSdk = surface.targetSdk,
            requestedPermissions = sortedRequestedPerms,
            declaredPermissions = sortedDeclaredPerms,
            exportedComponents = lockedComponents,
            deepLinks = allDeepLinks,
            nativeLibraries = nativeLibs,
            networkSecurity = lockedNetwork,
            sha256Fingerprint = sha256
        )
    }

    fun serialize(lock: SurfaceLock): String {
        return json.encodeToString(lock)
    }

    fun deserialize(jsonStr: String): SurfaceLock {
        return json.decodeFromString(jsonStr)
    }

    private fun formatDeepLink(link: DeepLink): String {
        val hostPart = if (link.host != null) "://${link.host}" else "://"
        val pathPart = link.path ?: ""
        return "${link.scheme}$hostPart$pathPart"
    }
}
