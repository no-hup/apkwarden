package io.apkwarden.core.surface

import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.model.*
import io.apkwarden.core.parser.ArscParser
import io.apkwarden.core.parser.AxmlNode
import io.apkwarden.core.parser.AxmlParser

class AttackSurfaceResolver(
    private val archive: ApkArchive,
    private val manifestNode: AxmlNode,
    private val arscParser: ArscParser?
) {

    fun resolve(): AttackSurface {
        val packageName = manifestNode.findAttribute("package")?.value ?: "unknown.package"
        val versionCode = manifestNode.findAttribute("versionCode")?.value?.toLongOrNull() ?: 1L
        val versionName = manifestNode.findAttribute("versionName")?.value

        // SDK versions
        val usesSdkNode = manifestNode.findChildren("uses-sdk").firstOrNull()
        val minSdk = usesSdkNode?.findAttribute("minSdkVersion")?.value?.toIntOrNull() ?: 1
        val targetSdk = usesSdkNode?.findAttribute("targetSdkVersion")?.value?.toIntOrNull() ?: minSdk
        val compileSdk = manifestNode.findAttribute("compileSdkVersion")?.value?.toIntOrNull()

        // Permissions declared
        val declaredPermissions = manifestNode.findChildren("permission").map { pNode ->
            val name = pNode.findAttribute("name")?.value ?: ""
            val rawProt = pNode.findAttribute("protectionLevel")?.value
            val level = parseProtectionLevel(rawProt)
            DeclaredPermission(name, level, rawProt)
        }

        // Permissions requested
        val requestedPermissions = manifestNode.findChildren("uses-permission").map { upNode ->
            val name = upNode.findAttribute("name")?.value ?: ""
            val maxSdk = upNode.findAttribute("maxSdkVersion")?.value?.toIntOrNull()
            RequestedPermission(name, maxSdk)
        }

        // Application node
        val appNode = manifestNode.findChildren("application").firstOrNull()
        val isDebuggable = appNode?.findAttribute("debuggable")?.booleanValue ?: false
        val isTestOnly = appNode?.findAttribute("testOnly")?.booleanValue ?: false
        val allowBackup = appNode?.findAttribute("allowBackup")?.booleanValue ?: true
        val dataExtractionRulesDefined = appNode?.findAttribute("dataExtractionRules") != null
        val applicationClass = resolveClassName(appNode?.findAttribute("name")?.value, packageName)

        // Network Security Config
        val networkSecurityConfig = resolveNetworkSecurityConfig(appNode)

        // Components & Deep Links
        val components = mutableListOf<Component>()
        val deepLinks = mutableListOf<DeepLink>()
        val fileProviderPaths = mutableListOf<FileProviderPath>()

        if (appNode != null) {
            // Activities
            for (node in appNode.findChildren("activity")) {
                val comp = parseComponent(node, ComponentType.ACTIVITY, packageName, targetSdk)
                components.add(comp)
                deepLinks.addAll(extractDeepLinks(comp))
            }

            // Activity Aliases
            for (node in appNode.findChildren("activity-alias")) {
                val targetAct = resolveClassName(node.findAttribute("targetActivity")?.value, packageName)
                val comp = parseComponent(node, ComponentType.ACTIVITY_ALIAS, packageName, targetSdk, targetAct)
                components.add(comp)
                deepLinks.addAll(extractDeepLinks(comp))
            }

            // Services
            for (node in appNode.findChildren("service")) {
                components.add(parseComponent(node, ComponentType.SERVICE, packageName, targetSdk))
            }

            // Receivers
            for (node in appNode.findChildren("receiver")) {
                components.add(parseComponent(node, ComponentType.RECEIVER, packageName, targetSdk))
            }

            // Providers
            for (node in appNode.findChildren("provider")) {
                val comp = parseComponent(node, ComponentType.PROVIDER, packageName, targetSdk)
                components.add(comp)
                // Check if FileProvider
                if (comp.name.contains("FileProvider") || comp.metadata.containsKey("android.support.FILE_PROVIDER_PATHS")) {
                    fileProviderPaths.addAll(resolveFileProviderPaths(node))
                }
            }
        }

        return AttackSurface(
            packageName = packageName,
            versionCode = versionCode,
            versionName = versionName,
            minSdk = minSdk,
            targetSdk = targetSdk,
            compileSdk = compileSdk,
            isDebuggable = isDebuggable,
            isTestOnly = isTestOnly,
            allowBackup = allowBackup,
            dataExtractionRulesDefined = dataExtractionRulesDefined,
            requestedPermissions = requestedPermissions,
            declaredPermissions = declaredPermissions,
            components = components,
            deepLinks = deepLinks,
            fileProviderPaths = fileProviderPaths,
            networkSecurityConfig = networkSecurityConfig,
            applicationClass = applicationClass
        )
    }

    private fun parseComponent(
        node: AxmlNode,
        type: ComponentType,
        packageName: String,
        targetSdk: Int,
        targetActivity: String? = null
    ): Component {
        val rawName = node.findAttribute("name")?.value ?: "Unknown${type.name}"
        val name = resolveClassName(rawName, packageName)

        val intentFilters = node.findChildren("intent-filter").map { parseIntentFilter(it) }

        // Exported status resolution
        val exportedAttr = node.findAttribute("exported")
        val exported = if (exportedAttr != null) {
            resolveBooleanAttribute(exportedAttr, targetSdk)
        } else {
            // Implicit export rule: If targetSdk < 31 and has intent filters, true; else false
            if (intentFilters.isNotEmpty() && targetSdk < 31) {
                true
            } else {
                false
            }
        }

        val permission = node.findAttribute("permission")?.value
        val readPermission = node.findAttribute("readPermission")?.value
        val writePermission = node.findAttribute("writePermission")?.value
        val grantUriPermissions = node.findAttribute("grantUriPermissions")?.booleanValue ?: false

        val authorities = node.findAttribute("authorities")?.value?.split(";")?.map { it.trim() } ?: emptyList()

        // Metadata
        val metadata = mutableMapOf<String, String>()
        for (mNode in node.findChildren("meta-data")) {
            val mName = mNode.findAttribute("name")?.value
            val mVal = mNode.findAttribute("value")?.value ?: mNode.findAttribute("resource")?.value
            if (mName != null && mVal != null) {
                metadata[mName] = mVal
            }
        }

        return Component(
            type = type,
            name = name,
            exported = exported,
            permission = permission,
            readPermission = readPermission,
            writePermission = writePermission,
            intentFilters = intentFilters,
            targetActivity = targetActivity,
            grantUriPermissions = grantUriPermissions,
            authorities = authorities,
            metadata = metadata,
            sourcePackage = inferSourcePackage(name, packageName)
        )
    }

    private fun resolveBooleanAttribute(attr: io.apkwarden.core.parser.AxmlAttribute, targetSdk: Int): Boolean {
        if (attr.isReference && arscParser != null) {
            val resId = attr.data
            val resolved = arscParser.resolveBoolean(resId, targetSdk)
            if (resolved != null) return resolved
        }
        return attr.booleanValue ?: attr.value.equals("true", ignoreCase = true)
    }

    private fun parseIntentFilter(node: AxmlNode): IntentFilter {
        val actions = node.findChildren("action").mapNotNull { it.findAttribute("name")?.value }
        val categories = node.findChildren("category").mapNotNull { it.findAttribute("name")?.value }
        val priority = node.findAttribute("priority")?.value?.toIntOrNull() ?: 0
        val autoVerify = node.findAttribute("autoVerify")?.booleanValue ?: false

        val dataNodes = node.findChildren("data")
        val schemes = dataNodes.mapNotNull { it.findAttribute("scheme")?.value }.distinct()
        val hosts = dataNodes.mapNotNull { it.findAttribute("host")?.value }.distinct()
        val paths = dataNodes.mapNotNull {
            it.findAttribute("path")?.value ?: it.findAttribute("pathPrefix")?.value ?: it.findAttribute("pathPattern")?.value
        }.distinct()
        val mimeTypes = dataNodes.mapNotNull { it.findAttribute("mimeType")?.value }.distinct()

        return IntentFilter(
            actions = actions,
            categories = categories,
            dataSchemes = schemes,
            dataHosts = hosts,
            dataPaths = paths,
            dataMimeTypes = mimeTypes,
            priority = priority,
            autoVerify = autoVerify
        )
    }

    private fun extractDeepLinks(component: Component): List<DeepLink> {
        val links = mutableListOf<DeepLink>()

        for (filter in component.intentFilters) {
            val isViewAction = filter.actions.contains("android.intent.action.VIEW")
            val isBrowsable = filter.categories.contains("android.intent.category.BROWSABLE")
            val isDefault = filter.categories.contains("android.intent.category.DEFAULT")

            if ((isViewAction && (isBrowsable || isDefault)) || filter.dataSchemes.isNotEmpty()) {
                val schemes = if (filter.dataSchemes.isNotEmpty()) filter.dataSchemes else listOf("content")
                val hosts = if (filter.dataHosts.isNotEmpty()) filter.dataHosts else listOf(null)
                val paths = if (filter.dataPaths.isNotEmpty()) filter.dataPaths else listOf(null)

                // Cartesian product of scheme x host x path
                for (scheme in schemes) {
                    for (host in hosts) {
                        for (path in paths) {
                            val isAutoVerify = filter.autoVerify && (scheme == "http" || scheme == "https")
                            links.add(
                                DeepLink(
                                    scheme = scheme,
                                    host = host,
                                    path = path,
                                    autoVerify = isAutoVerify,
                                    targetComponent = component.name
                                )
                            )
                        }
                    }
                }
            }
        }

        return links
    }

    private fun resolveFileProviderPaths(providerNode: AxmlNode): List<FileProviderPath> {
        val paths = mutableListOf<FileProviderPath>()
        val metaData = providerNode.findChildren("meta-data").firstOrNull {
            it.findAttribute("name")?.value == "android.support.FILE_PROVIDER_PATHS"
        } ?: return emptyList()

        val resourceAttr = metaData.findAttribute("resource") ?: return emptyList()
        val xmlPath = resolveResourcePath(resourceAttr.data, resourceAttr.value) ?: return emptyList()

        val bytes = archive.getEntryBytes(xmlPath) ?: return emptyList()
        try {
            val xmlNode = AxmlParser(bytes).parse()
            for (child in xmlNode.children) {
                val tag = child.tag
                val name = child.findAttribute("name")?.value ?: ""
                val path = child.findAttribute("path")?.value ?: ""

                val isRoot = tag == "root-path"
                val isBroad = path == "." || path.isEmpty()

                paths.add(
                    FileProviderPath(
                        tag = tag,
                        name = name,
                        path = path,
                        isRootPath = isRoot,
                        isBroadWildcard = isBroad
                    )
                )
            }
        } catch (_: Exception) {
            // Ignore corrupted or non-AXML resource
        }

        return paths
    }

    private fun resolveNetworkSecurityConfig(appNode: AxmlNode?): NetworkSecurityConfig? {
        val attr = appNode?.findAttribute("networkSecurityConfig") ?: return null
        val xmlPath = resolveResourcePath(attr.data, attr.value) ?: return null

        val bytes = archive.getEntryBytes(xmlPath) ?: return null
        return try {
            val xml = AxmlParser(bytes).parse()
            parseNetworkSecurityXml(xml)
        } catch (_: Exception) {
            null
        }
    }

    private fun parseNetworkSecurityXml(root: AxmlNode): NetworkSecurityConfig {
        var baseCleartext = true
        var globalUserTrust = false
        val domainConfigs = mutableListOf<NetworkDomainConfig>()

        val baseConfig = root.findChildren("base-config").firstOrNull()
        if (baseConfig != null) {
            baseCleartext = baseConfig.findAttribute("cleartextTrafficPermitted")?.booleanValue ?: true
            val trustAnchors = baseConfig.findChildren("trust-anchors").firstOrNull()
            if (trustAnchors?.findChildren("certificates")?.any { it.findAttribute("src")?.value == "user" } == true) {
                globalUserTrust = true
            }
        }

        for (domainNode in root.findChildren("domain-config")) {
            val cleartext = domainNode.findAttribute("cleartextTrafficPermitted")?.booleanValue ?: baseCleartext
            val subdomains = domainNode.findChildren("domain").any { it.findAttribute("includeSubdomains")?.booleanValue ?: false }
            val domainNodeChild = domainNode.findChildren("domain").firstOrNull()
            val domainName = domainNodeChild?.findAttribute("name")?.value ?: domainNodeChild?.text ?: "unknown"

            val trustAnchors = domainNode.findChildren("trust-anchors").firstOrNull()
            val userTrust = trustAnchors?.findChildren("certificates")?.any { it.findAttribute("src")?.value == "user" } == true

            val pins = domainNode.findChildren("pin-set").flatMap { ps ->
                ps.findChildren("pin").mapNotNull { it.findAttribute("digest")?.value ?: it.text }
            }

            domainConfigs.add(
                NetworkDomainConfig(
                    domain = domainName,
                    includeSubdomains = subdomains,
                    cleartextPermitted = cleartext,
                    certificatePins = pins,
                    trustUserCerts = userTrust
                )
            )
        }

        return NetworkSecurityConfig(
            baseCleartextPermitted = baseCleartext,
            domainConfigs = domainConfigs,
            trustUserCertsGlobally = globalUserTrust
        )
    }

    private fun resolveResourcePath(resId: Int, rawValue: String?): String? {
        if (arscParser != null && resId != 0) {
            val resolved = arscParser.resolvePath(resId)
            if (resolved != null && resolved.startsWith("res/")) {
                return resolved
            }
        }
        if (rawValue != null && rawValue.startsWith("res/")) {
            return rawValue
        }
        return null
    }

    private fun resolveClassName(rawName: String?, packageName: String): String {
        if (rawName == null) return "Unknown"
        return when {
            rawName.startsWith(".") -> "$packageName$rawName"
            !rawName.contains(".") -> "$packageName.$rawName"
            else -> rawName
        }
    }

    private fun parseProtectionLevel(raw: String?): ProtectionLevel {
        if (raw == null) return ProtectionLevel.NORMAL
        val normalized = raw.lowercase()
        return when {
            normalized.contains("signatureorsystem") -> ProtectionLevel.SIGNATURE_OR_SYSTEM
            normalized.contains("signature") -> ProtectionLevel.SIGNATURE
            normalized.contains("dangerous") -> ProtectionLevel.DANGEROUS
            normalized.contains("internal") -> ProtectionLevel.INTERNAL
            normalized.contains("normal") -> ProtectionLevel.NORMAL
            else -> ProtectionLevel.NORMAL
        }
    }

    private fun inferSourcePackage(className: String, appPackage: String): String {
        return when {
            className.startsWith(appPackage) -> "first-party"
            className.startsWith("com.google.") || className.startsWith("com.google.android.") -> "Google Play / Firebase"
            className.startsWith("androidx.") -> "AndroidX"
            className.startsWith("com.facebook.") -> "Facebook SDK"
            className.startsWith("com.adjust.") -> "Adjust Analytics"
            className.startsWith("com.appsflyer.") -> "AppsFlyer"
            className.startsWith("io.sentry.") -> "Sentry"
            else -> {
                val parts = className.split(".")
                if (parts.size >= 2) "${parts[0]}.${parts[1]}" else "third-party"
            }
        }
    }
}
