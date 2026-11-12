package io.apkwarden.core.lock

import io.apkwarden.core.model.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SurfaceLockGeneratorTest {

    @Test
    fun `generates deterministic sorted lockfile`() {
        val comp1 = Component(
            type = ComponentType.ACTIVITY,
            name = "com.example.b.ZActivity",
            exported = true,
            permission = "android.permission.CAMERA"
        )
        val comp2 = Component(
            type = ComponentType.ACTIVITY,
            name = "com.example.a.AActivity",
            exported = true,
            permission = null
        )

        val surface = AttackSurface(
            packageName = "com.example.app",
            versionCode = 42,
            versionName = "1.0.0",
            minSdk = 24,
            targetSdk = 34,
            compileSdk = 34,
            isDebuggable = false,
            isTestOnly = false,
            allowBackup = true,
            dataExtractionRulesDefined = false,
            requestedPermissions = listOf(
                RequestedPermission("android.permission.INTERNET"),
                RequestedPermission("android.permission.ACCESS_FINE_LOCATION")
            ),
            components = listOf(comp1, comp2)
        )

        val lock1 = SurfaceLockGenerator.generate(surface)
        val lock2 = SurfaceLockGenerator.generate(surface)

        // Sorted check
        assertThat(lock1.requestedPermissions).containsExactly(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET"
        )
        assertThat(lock1.exportedComponents.map { it.name }).containsExactly(
            "com.example.a.AActivity",
            "com.example.b.ZActivity"
        )

        // Exact reproducibility of SHA-256 fingerprint
        assertThat(lock1.sha256Fingerprint).isEqualTo(lock2.sha256Fingerprint)
        assertThat(lock1.sha256Fingerprint).isNotEmpty()

        val json = SurfaceLockGenerator.serialize(lock1)
        assertThat(json).contains("\"packageName\": \"com.example.app\"")
        assertThat(json).contains("\"targetSdk\": 34")
    }
}
