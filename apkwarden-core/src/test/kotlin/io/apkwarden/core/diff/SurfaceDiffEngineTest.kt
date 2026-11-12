package io.apkwarden.core.diff

import io.apkwarden.core.model.LockedComponent
import io.apkwarden.core.model.LockedNetworkConfig
import io.apkwarden.core.model.SurfaceLock
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SurfaceDiffEngineTest {

    private fun createLock(
        packageName: String = "com.example.app",
        minSdk: Int = 26,
        targetSdk: Int = 34,
        permissions: List<String> = listOf("android.permission.INTERNET"),
        components: List<LockedComponent> = emptyList(),
        networkConfig: LockedNetworkConfig? = LockedNetworkConfig(
            baseCleartextPermitted = false,
            cleartextDomains = emptyList(),
            pinnedDomains = emptyList(),
            trustsUserCerts = false
        )
    ): SurfaceLock {
        return SurfaceLock(
            schemaVersion = 1,
            packageName = packageName,
            minSdk = minSdk,
            targetSdk = targetSdk,
            requestedPermissions = permissions,
            declaredPermissions = emptyList(),
            exportedComponents = components,
            deepLinks = emptyList(),
            nativeLibraries = emptyList(),
            networkSecurity = networkConfig,
            sha256Fingerprint = "dummy"
        )
    }

    @Test
    fun `detects zero drift when locks are identical`() {
        val lock = createLock()
        val result = SurfaceDiffEngine.diff(lock, lock)
        assertThat(result.hasBreakingChanges).isFalse()
        assertThat(result.totalChanges).isEqualTo(0)
    }

    @Test
    fun `detects added exported unguarded component as breaking change`() {
        val base = createLock()
        val head = createLock(
            components = listOf(
                LockedComponent(
                    type = "ACTIVITY",
                    name = "com.example.ExportedActivity",
                    exported = true,
                    permission = null // Unguarded!
                )
            )
        )

        val result = SurfaceDiffEngine.diff(base, head)
        assertThat(result.hasBreakingChanges).isTrue()
        assertThat(result.breakingCount).isEqualTo(1)
        assertThat(result.addedExportedComponents).hasSize(1)
        assertThat(result.diffItems[0].message).contains("New exported component added")
        assertThat(result.diffItems[0].detail).contains("UNGUARDED")
    }

    @Test
    fun `detects added dangerous runtime permission as breaking`() {
        val base = createLock(permissions = listOf("android.permission.INTERNET"))
        val head = createLock(permissions = listOf("android.permission.INTERNET", "android.permission.CAMERA"))

        val result = SurfaceDiffEngine.diff(base, head)
        assertThat(result.hasBreakingChanges).isTrue()
        assertThat(result.addedPermissions).containsExactly("android.permission.CAMERA")
        assertThat(result.diffItems.any { it.message.contains("android.permission.CAMERA") && it.severity == DiffSeverity.BREAKING }).isTrue()
    }

    @Test
    fun `detects targetSdk downgrade and cleartext enabled as breaking`() {
        val base = createLock(
            targetSdk = 34,
            networkConfig = LockedNetworkConfig(
                baseCleartextPermitted = false,
                cleartextDomains = emptyList(),
                pinnedDomains = emptyList(),
                trustsUserCerts = false
            )
        )
        val head = createLock(
            targetSdk = 28,
            networkConfig = LockedNetworkConfig(
                baseCleartextPermitted = true,
                cleartextDomains = emptyList(),
                pinnedDomains = emptyList(),
                trustsUserCerts = false
            )
        )

        val result = SurfaceDiffEngine.diff(base, head)
        assertThat(result.hasBreakingChanges).isTrue()
        assertThat(result.breakingCount).isGreaterThanOrEqualTo(2)
        assertThat(result.diffItems.any { it.category == "SDK" && it.severity == DiffSeverity.BREAKING }).isTrue()
        assertThat(result.diffItems.any { it.category == "NETWORK" && it.severity == DiffSeverity.BREAKING }).isTrue()
    }
}
