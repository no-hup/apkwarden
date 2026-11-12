package io.apkwarden.core.diff

import io.apkwarden.core.model.LockedComponent
import io.apkwarden.core.model.SurfaceLock

object SurfaceDiffEngine {

    private val dangerousPermissions = setOf(
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.BODY_SENSORS",
        "android.permission.BODY_SENSORS_BACKGROUND",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_MEDIA_LOCATION",
        "android.permission.POST_NOTIFICATIONS",
        "android.permission.NEARBY_WIFI_DEVICES",
        "android.permission.BLUETOOTH_SCAN",
        "android.permission.BLUETOOTH_CONNECT",
        "android.permission.BLUETOOTH_ADVERTISE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_MEDIA_AUDIO"
    )

    fun diff(base: SurfaceLock, head: SurfaceLock): SurfaceDiffResult {
        val diffItems = mutableListOf<DiffItem>()

        // 0. Package Identity Validation
        if (base.packageName != head.packageName && base.packageName.isNotEmpty()) {
            diffItems.add(
                DiffItem(
                    category = "PACKAGE",
                    severity = DiffSeverity.BREAKING,
                    message = "Package name changed from '${base.packageName}' to '${head.packageName}'"
                )
            )
        }

        // 1. SDK changes
        if (head.targetSdk < base.targetSdk) {
            diffItems.add(
                DiffItem(
                    category = "SDK",
                    severity = DiffSeverity.BREAKING,
                    message = "Target SDK downgraded: ${base.targetSdk} -> ${head.targetSdk}",
                    detail = "Downgrading targetSdk bypasses newer platform security mitigations."
                )
            )
        } else if (head.targetSdk > base.targetSdk) {
            diffItems.add(
                DiffItem(
                    category = "SDK",
                    severity = DiffSeverity.INFO,
                    message = "Target SDK upgraded: ${base.targetSdk} -> ${head.targetSdk}"
                )
            )
        }

        if (head.minSdk < base.minSdk) {
            diffItems.add(
                DiffItem(
                    category = "SDK",
                    severity = DiffSeverity.WARNING,
                    message = "Min SDK lowered: ${base.minSdk} -> ${head.minSdk}",
                    detail = "Lowering minSdk exposes app to vulnerabilities present in older Android releases."
                )
            )
        }

        // 2. Exported Components
        val baseComponents = base.exportedComponents.associateBy { "${it.type}:${it.name}" }
        val headComponents = head.exportedComponents.associateBy { "${it.type}:${it.name}" }

        val addedComponents = mutableListOf<LockedComponent>()
        val removedComponents = mutableListOf<LockedComponent>()

        for ((key, headComp) in headComponents) {
            val baseComp = baseComponents[key]
            if (baseComp == null) {
                addedComponents.add(headComp)
                val isUnguarded = headComp.permission == null && headComp.readPermission == null && headComp.writePermission == null
                diffItems.add(
                    DiffItem(
                        category = "COMPONENT",
                        severity = DiffSeverity.BREAKING,
                        message = "New exported component added: [${headComp.type}] ${headComp.name}",
                        detail = if (isUnguarded) "⚠️ UNGUARDED: Component has no protecting permissions!" else "Protected by: ${headComp.permission}"
                    )
                )
            } else {
                // Check if permission was weakened
                if (baseComp.permission != null && headComp.permission == null) {
                    diffItems.add(
                        DiffItem(
                            category = "COMPONENT",
                            severity = DiffSeverity.BREAKING,
                            message = "Permission guard removed from [${headComp.type}] ${headComp.name}",
                            detail = "Previously required: ${baseComp.permission}"
                        )
                    )
                }

                if (baseComp.readPermission != null && headComp.readPermission == null) {
                    diffItems.add(
                        DiffItem(
                            category = "COMPONENT",
                            severity = DiffSeverity.BREAKING,
                            message = "Exported provider '${headComp.name}' removed readPermission guard",
                            detail = "Previously required readPermission: ${baseComp.readPermission}"
                        )
                    )
                }

                if (baseComp.writePermission != null && headComp.writePermission == null) {
                    diffItems.add(
                        DiffItem(
                            category = "COMPONENT",
                            severity = DiffSeverity.BREAKING,
                            message = "Exported provider '${headComp.name}' removed writePermission guard",
                            detail = "Previously required writePermission: ${baseComp.writePermission}"
                        )
                    )
                }

                // Check if per-component deep links added to an existing exported component
                val newCompDeepLinks = (headComp.deepLinks.toSet() - baseComp.deepLinks.toSet()).sorted()
                for (dl in newCompDeepLinks) {
                    diffItems.add(
                        DiffItem(
                            category = "COMPONENT",
                            severity = DiffSeverity.WARNING,
                            message = "New deep link added to exported [${headComp.type}] ${headComp.name}: $dl"
                        )
                    )
                }

                // Check if provider authorities added to existing provider
                val newAuthorities = (headComp.authorities.toSet() - baseComp.authorities.toSet()).sorted()
                for (auth in newAuthorities) {
                    diffItems.add(
                        DiffItem(
                            category = "COMPONENT",
                            severity = DiffSeverity.BREAKING,
                            message = "New authority added to exported provider [${headComp.name}]: $auth"
                        )
                    )
                }
            }
        }

        for ((key, baseComp) in baseComponents) {
            if (!headComponents.containsKey(key)) {
                removedComponents.add(baseComp)
                diffItems.add(
                    DiffItem(
                        category = "COMPONENT",
                        severity = DiffSeverity.INFO,
                        message = "Exported component removed: [${baseComp.type}] ${baseComp.name}"
                    )
                )
            }
        }

        // 3. Permissions
        val basePerms = base.requestedPermissions.toSet()
        val headPerms = head.requestedPermissions.toSet()

        val addedPerms = (headPerms - basePerms).sorted()
        val removedPerms = (basePerms - headPerms).sorted()

        for (perm in addedPerms) {
            val isDangerous = dangerousPermissions.contains(perm)
            diffItems.add(
                DiffItem(
                    category = "PERMISSION",
                    severity = if (isDangerous) DiffSeverity.BREAKING else DiffSeverity.WARNING,
                    message = "New permission requested: $perm",
                    detail = if (isDangerous) "🚨 High-risk runtime permission" else null
                )
            )
        }

        for (perm in removedPerms) {
            diffItems.add(
                DiffItem(
                    category = "PERMISSION",
                    severity = DiffSeverity.INFO,
                    message = "Permission removed: $perm"
                )
            )
        }

        // 4. Network Security Config
        val baseNsc = base.networkSecurity
        val headNsc = head.networkSecurity

        if (baseNsc != null && headNsc != null) {
            if (!baseNsc.baseCleartextPermitted && headNsc.baseCleartextPermitted) {
                diffItems.add(
                    DiffItem(
                        category = "NETWORK",
                        severity = DiffSeverity.BREAKING,
                        message = "Base cleartext HTTP traffic was enabled (baseCleartextPermitted: false -> true)"
                    )
                )
            }
            if (!baseNsc.trustsUserCerts && headNsc.trustsUserCerts) {
                diffItems.add(
                    DiffItem(
                        category = "NETWORK",
                        severity = DiffSeverity.BREAKING,
                        message = "User installed CA certificates are now trusted (trustsUserCerts: false -> true)"
                    )
                )
            }
            val addedCleartextDomains = (headNsc.cleartextDomains.toSet() - baseNsc.cleartextDomains.toSet()).sorted()
            for (domain in addedCleartextDomains) {
                diffItems.add(
                    DiffItem(
                        category = "NETWORK",
                        severity = DiffSeverity.WARNING,
                        message = "Cleartext HTTP traffic enabled for domain: $domain"
                    )
                )
            }
            val removedPins = (baseNsc.pinnedDomains.toSet() - headNsc.pinnedDomains.toSet()).sorted()
            for (domain in removedPins) {
                diffItems.add(
                    DiffItem(
                        category = "NETWORK",
                        severity = DiffSeverity.BREAKING,
                        message = "Certificate pinning removed for domain: $domain"
                    )
                )
            }
        } else if (baseNsc != null && headNsc == null) {
            diffItems.add(
                DiffItem(
                    category = "NETWORK",
                    severity = DiffSeverity.BREAKING,
                    message = "Network Security Config was removed entirely from the application",
                    detail = "Any previous certificate pins or cleartext HTTP restrictions have been dismantled."
                )
            )
        } else if (baseNsc == null && headNsc != null) {
            diffItems.add(
                DiffItem(
                    category = "NETWORK",
                    severity = DiffSeverity.INFO,
                    message = "Network Security Config was added to the application"
                )
            )
            if (headNsc.baseCleartextPermitted) {
                diffItems.add(
                    DiffItem(
                        category = "NETWORK",
                        severity = DiffSeverity.BREAKING,
                        message = "Base cleartext HTTP traffic is explicitly permitted in newly added Network Security Config"
                    )
                )
            }
        }

        // 5. Deep Links
        val baseLinks = base.deepLinks.toSet()
        val headLinks = head.deepLinks.toSet()
        val addedLinks = (headLinks - baseLinks).sorted()
        for (link in addedLinks) {
            diffItems.add(
                DiffItem(
                    category = "DEEP_LINK",
                    severity = DiffSeverity.WARNING,
                    message = "New deep link scheme/pattern added: $link"
                )
            )
        }

        val breakingCount = diffItems.count { it.severity == DiffSeverity.BREAKING }
        val warningCount = diffItems.count { it.severity == DiffSeverity.WARNING }
        val infoCount = diffItems.count { it.severity == DiffSeverity.INFO }

        return SurfaceDiffResult(
            basePackageName = base.packageName,
            headPackageName = head.packageName,
            hasBreakingChanges = breakingCount > 0,
            totalChanges = diffItems.size,
            breakingCount = breakingCount,
            warningCount = warningCount,
            infoCount = infoCount,
            addedExportedComponents = addedComponents,
            removedExportedComponents = removedComponents,
            addedPermissions = addedPerms,
            removedPermissions = removedPerms,
            diffItems = diffItems
        )
    }
}
