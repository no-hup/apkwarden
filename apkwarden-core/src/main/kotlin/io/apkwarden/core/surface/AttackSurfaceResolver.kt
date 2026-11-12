package io.apkwarden.core.surface

import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.model.*
import io.apkwarden.core.parser.AndroidResIds
import io.apkwarden.core.parser.ArscParser
import io.apkwarden.core.parser.AxmlNode
import io.apkwarden.core.parser.AxmlParser

class AttackSurfaceResolver(
    private val archive: ApkArchive,
    private val manifestNode: AxmlNode,
    private val arscParser: ArscParser?
) {

    fun resolve(): AttackSurface {
        val rawPackageName = manifestNode.findAttribute("package")?.value ?: "unknown.package"
        val packageName = sanitizeText(rawPackageName)
        val versionCode = manifestNode.findAttribute("versionCode")?.value?.toLongOrNull() ?: 1L
        val versionName = manifestNode.findAttribute("versionName")?.value?.let { sanitizeText(it) }

        // SDK versions
        val usesSdkNode = manifestNode.findChildren("uses-sdk").firstOrNull()
        val minSdk = usesSdkNode?.findAttribute("minSdkVersion")?.value?.toIntOrNull() ?: 1
        val targetSdk = usesSdkNode?.findAttribute("targetSdkVersion")?.value?.toIntOrNull() ?: minSdk
        val compileSdk = manifestNode.findAttribute("compileSdkVersion")?.value?.toIntOrNull()

        // Permissions declared
        val declaredPermissions = manifestNode.findChildren("permission").map { pNode ->
            val name = sanitizeText(pNode.findAttribute("name", AndroidResIds.ATTR_NAME)?.value ?: "")
            val rawProt = pNode.findAttribute("protectionLevel")?.value
            val level = parseProtectionLevel(rawProt)
            DeclaredPermission(name, level, rawProt)
        }

        // Permissions requested
        val requestedPermissions = manifestNode.findChildren("uses-permission").map { upNode ->
            val name = sanitizeText(upNode.findAttribute("name", AndroidResIds.ATTR_NAME)?.value ?: "")
            val maxSdk = upNode.findAttribute("maxSdkVersion")?.value?.toIntOrNull()
            RequestedPermission(name, maxSdk)
        }

        // Application node
        val appNode = manifestNode.findChildren("application").firstOrNull()
        val isDebuggable = appNode?.findAttribute("debuggable")?.booleanValue ?: false
        val isTestOnly = appNode?.findAttribute("testOnly")?.booleanValue ?: false
        val allowBackup = appNode?.findAttribute("allowBackup")?.booleanValue ?: true
        val dataExtractionRulesDefined = appNode?.findAttribute("dataExtractionRules") != null
        val usesCleartextTraffic = appNode?.findAttribute("usesCleartextTraffic")?.booleanValue
        val applicationClass = resolveClassName(appNode?.findAttribute("name", AndroidResIds.ATTR_NAME)?.value, packageName)
        val appPermission = appNode?.findAttribute("permission", AndroidResIds.ATTR_PERMISSION)?.value?.let { sanitizeText(it) }

        // Network Security Config
        val networkSecurityConfig = resolveNetworkSecurityConfig(appNode, targetSdk)

        // Components & Deep Links
        val components = mutableListOf<Component>()
        val deepLinks = mutableListOf<DeepLink>()
        val fileProviderPaths = mutableListOf<FileProviderPath>()

        if (appNode != null) {
            // Activities
            for (node in appNode.findChildren("activity")) {
                val comp = parseComponent(node, ComponentType.ACTIVITY, packageName, targetSdk, appPermission = appPermission)
                components.add(comp)
                deepLinks.addAll(extractDeepLinks(comp))
            }

            // Activity Aliases
            for (node in appNode.findChildren("activity-alias")) {
                val targetAct = resolveClassName(node.findAttribute("targetActivity")?.value, packageName)
                val comp = parseComponent(node, ComponentType.ACTIVITY_ALIAS, packageName, targetSdk, targetAct, appPermission)
                components.add(comp)
                deepLinks.addAll(extractDeepLinks(comp))
            }

            // Services
            for (node in appNode.findChildren("service")) {
                components.add(parseComponent(node, ComponentType.SERVICE, packageName, targetSdk, appPermission = appPermission))
            }

            // Receivers
            for (node in appNode.findChildren("receiver")) {
                components.add(parseComponent(node, ComponentType.RECEIVER, packageName, targetSdk, appPermission = appPermission))
            }

            // Providers
            for (node in appNode.findChildren("provider")) {
                val comp = parseComponent(node, ComponentType.PROVIDER, packageName, targetSdk, appPermission = appPermission)
                components.add(comp)
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
            usesCleartextTraffic = usesCleartextTraffic,
            applicationClass = applicationClass
        )
    }

    private fun parseComponent(
        node: AxmlNode,
        type: ComponentType,
        packageName: String,
        targetSdk: Int,
        targetActivity: String? = null,
        appPermission: String? = null
    ): Component {
        val rawName = node.findAttribute("name", AndroidResIds.ATTR_NAME)?.value ?: "Unknown${type.name}"
        val name = sanitizeText(resolveClassName(rawName, packageName))

        val intentFilters = node.findChildren("intent-filter").map { parseIntentFilter(it) }

        // Exported status resolution per component type
        val exportedAttr = node.findAttribute("exported", AndroidResIds.ATTR_EXPORTED)
        val (exported, exportStatus) = if (type == ComponentType.PROVIDER) {
            if (exportedAttr != null) {
                val isExp = resolveBooleanAttribute(exportedAttr, targetSdk)
                isExp to (if (isExp) ExportStatus.EXPLICIT_EXPORTED else ExportStatus.NOT_EXPORTED)
            } else {
                // By Android platform rules, ContentProviders default to exported=true on targetSdk <= 16, false thereafter
                val isExp = targetSdk <= 16
                isExp to (if (isExp) ExportStatus.IMPLICIT_EXPORTED else ExportStatus.NOT_EXPORTED)
            }
        } else {
            if (exportedAttr != null) {
                val isExp = resolveBooleanAttribute(exportedAttr, targetSdk)
                isExp to (if (isExp) ExportStatus.EXPLICIT_EXPORTED else ExportStatus.NOT_EXPORTED)
            } else {
                if (intentFilters.isNotEmpty()) {
                    if (targetSdk < 31) {
                        true to ExportStatus.IMPLICIT_EXPORTED
                    } else {
                        // On targetSdk >= 31, Android 12+ refuses to install missing exported attribute,
                        // but pre-Android 12 devices install and treat it as exported!
                        true to ExportStatus.EXPORTED_ON_LEGACY_ONLY
                    }
                } else {
                    false to ExportStatus.NOT_EXPORTED
                }
            }
        }

        val directPermission = node.findAttribute("permission", AndroidResIds.ATTR_PERMISSION)?.value?.let { sanitizeText(it) }
        val permission = directPermission ?: appPermission
        val readPermission = node.findAttribute("readPermission", AndroidResIds.ATTR_READ_PERMISSION)?.value?.let { sanitizeText(it) }
        val writePermission = node.findAttribute("writePermission", AndroidResIds.ATTR_WRITE_PERMISSION)?.value?.let { sanitizeText(it) }
        val grantUriPermissions = node.findAttribute("grantUriPermissions", AndroidResIds.ATTR_GRANT_URI_PERMISSIONS)?.booleanValue ?: false

        val authorities = node.findAttribute("authorities", AndroidResIds.ATTR_AUTHORITIES)?.value?.split(";")?.map { sanitizeText(it.trim()) } ?: emptyList()

        // Metadata
        val metadata = mutableMapOf<String, String>()
        for (mNode in node.findChildren("meta-data")) {
            val mName = mNode.findAttribute("name", AndroidResIds.ATTR_NAME)?.value
            val mVal = mNode.findAttribute("value")?.value ?: mNode.findAttribute("resource")?.value
            if (mName != null && mVal != null) {
                metadata[sanitizeText(mName)] = sanitizeText(mVal)
            }
        }

        return Component(
            type = type,
            name = name,
            exported = exported,
            exportStatus = exportStatus,
            permission = permission,
            readPermission = readPermission,
            writePermission = writePermission,
            intentFilters = intentFilters,
            targetActivity = targetActivity?.let { sanitizeText(it) },
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
        val actions = node.findChildren("action").mapNotNull { it.findAttribute("name", AndroidResIds.ATTR_NAME)?.value }.map { sanitizeText(it) }
        val categories = node.findChildren("category").mapNotNull { it.findAttribute("name", AndroidResIds.ATTR_NAME)?.value }.map { sanitizeText(it) }
        val priority = node.findAttribute("priority")?.value?.toIntOrNull() ?: 0
        val autoVerify = node.findAttribute("autoVerify", AndroidResIds.ATTR_AUTOVERIFY)?.booleanValue ?: false

        val dataNodes = node.findChildren("data")
        val schemes = dataNodes.mapNotNull { it.findAttribute("scheme", AndroidResIds.ATTR_SCHEME)?.value }.map { sanitizeText(it) }.distinct()
        val hosts = dataNodes.mapNotNull { it.findAttribute("host", AndroidResIds.ATTR_HOST)?.value }.map { sanitizeText(it) }.distinct()
        val paths = dataNodes.mapNotNull {
            it.findAttribute("path", AndroidResIds.ATTR_PATH)?.value ?:
            it.findAttribute("pathPrefix", AndroidResIds.ATTR_PATH_PREFIX)?.value ?:
            it.findAttribute("pathPattern", AndroidResIds.ATTR_PATH_PATTERN)?.value
        }.map { sanitizeText(it) }.distinct()
        val mimeTypes = dataNodes.mapNotNull { it.findAttribute("mimeType", AndroidResIds.ATTR_MIME_TYPE)?.value }.map { sanitizeText(it) }.distinct()

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
                val schemes = filter.dataSchemes.ifEmpty { listOf("content") }
                val hosts = filter.dataHosts.ifEmpty { listOf(null) }
                val paths = filter.dataPaths.ifEmpty { listOf(null) }

                var count = 0
                for (scheme in schemes) {
                    for (host in hosts) {
                        for (path in paths) {
                            if (count++ >= 50) break
                            val isAutoVerify = filter.autoVerify && (scheme == "http" || scheme == "https")
                            links.add(
                                DeepLink(
                                    scheme = sanitizeText(scheme),
                                    host = host?.let { sanitizeText(it) },
                                    path = path?.let { sanitizeText(it) },
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
                val isBroad = path == "." || path.isEmpty() || path == "/"

                paths.add(
                    FileProviderPath(
                        tag = tag,
                        name = sanitizeText(name),
                        path = sanitizeText(path),
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

    private fun resolveNetworkSecurityConfig(appNode: AxmlNode?, targetSdk: Int): NetworkSecurityConfig? {
        val attr = appNode?.findAttribute("networkSecurityConfig") ?: return null
        val xmlPath = resolveResourcePath(attr.data, attr.value) ?: return null

        val bytes = archive.getEntryBytes(xmlPath) ?: return null
        return try {
            val xml = AxmlParser(bytes).parse()
            parseNetworkSecurityXml(xml, targetSdk)
        } catch (_: Exception) {
            null
        }
    }

    private fun parseNetworkSecurityXml(root: AxmlNode, targetSdk: Int): NetworkSecurityConfig {
        // Platform defaults by targetSdk:
        // Cleartext allowed by default on targetSdk <= 27, disallowed on targetSdk >= 28
        var baseCleartext = targetSdk <= 27
        // User certs trusted by default on targetSdk <= 23, disallowed on targetSdk >= 24
        var globalUserTrust = targetSdk <= 23
        val domainConfigs = mutableListOf<NetworkDomainConfig>()

        val baseConfig = root.findChildren("base-config").firstOrNull()
        if (baseConfig != null) {
            baseCleartext = baseConfig.findAttribute("cleartextTrafficPermitted")?.booleanValue ?: baseCleartext
            val trustAnchors = baseConfig.findChildren("trust-anchors").firstOrNull()
            if (trustAnchors?.findChildren("certificates")?.any { it.findAttribute("src")?.value == "user" } == true) {
                globalUserTrust = true
            }
        }

        for (domainNode in root.findChildren("domain-config")) {
            val cleartext = domainNode.findAttribute("cleartextTrafficPermitted")?.booleanValue ?: baseCleartext
            val subdomains = domainNode.findChildren("domain").any { it.findAttribute("includeSubdomains")?.booleanValue ?: false }
            val domainNodeChild = domainNode.findChildren("domain").firstOrNull()
            val domainName = sanitizeText(domainNodeChild?.findAttribute("name")?.value ?: domainNodeChild?.text ?: "unknown")

            val trustAnchors = domainNode.findChildren("trust-anchors").firstOrNull()
            val userTrust = trustAnchors?.findChildren("certificates")?.any { it.findAttribute("src")?.value == "user" } == true

            val pins = domainNode.findChildren("pin-set").flatMap { ps ->
                ps.findChildren("pin").mapNotNull { pinNode ->
                    (pinNode.findAttribute("digest")?.value ?: pinNode.text)?.let { sanitizeText(it) }
                }
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

    private fun sanitizeText(input: String): String {
        return input.replace(Regex("""\u001B\[[;?0-9]*[a-zA-Z]"""), "")
            .replace(Regex("""[\u0000-\u001F\u007F-\u009F]"""), "")
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
