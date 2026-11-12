package io.apkwarden.core.surface

import io.apkwarden.core.ingest.HardenedZipReader
import io.apkwarden.core.model.ComponentType
import io.apkwarden.core.parser.AxmlAttribute
import io.apkwarden.core.parser.AxmlNode
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class AttackSurfaceResolverTest {

    @Test
    fun `resolves implicit export on targetSdk 30 with intent filter`() {
        val actionNode = AxmlNode(
            tag = "action",
            attributes = listOf(AxmlAttribute(null, "name", "android.intent.action.VIEW", "android.intent.action.VIEW", 0, 3, 0)),
            children = emptyList()
        )
        val filterNode = AxmlNode(tag = "intent-filter", attributes = emptyList(), children = listOf(actionNode))

        // Activity has no explicit android:exported attribute
        val activityNode = AxmlNode(
            tag = "activity",
            attributes = listOf(AxmlAttribute(null, "name", ".ImplicitExportActivity", ".ImplicitExportActivity", 0, 3, 0)),
            children = listOf(filterNode)
        )

        val appNode = AxmlNode(tag = "application", attributes = emptyList(), children = listOf(activityNode))
        val usesSdkNode = AxmlNode(
            tag = "uses-sdk",
            attributes = listOf(AxmlAttribute(null, "targetSdkVersion", "30", "30", 0, 16, 30)),
            children = emptyList()
        )
        val manifestNode = AxmlNode(
            tag = "manifest",
            attributes = listOf(AxmlAttribute(null, "package", "com.example.test", "com.example.test", 0, 3, 0)),
            children = listOf(usesSdkNode, appNode)
        )

        val dummyArchive = HardenedZipReader("test.apk", createEmptyZip())
        val surface = AttackSurfaceResolver(dummyArchive, manifestNode, null).resolve()

        val comp = surface.components.first { it.name == "com.example.test.ImplicitExportActivity" }
        // On targetSdk 30, having an intent-filter makes it IMPLICITLY EXPORTED!
        assertThat(comp.exported).isTrue()
        assertThat(comp.exportStatus).isEqualTo(io.apkwarden.core.model.ExportStatus.IMPLICIT_EXPORTED)
    }

    @Test
    fun `resolves provider default export by targetSdk rather than intent filters`() {
        // Provider on targetSdk 16 with no attribute -> default exported=true
        val provNode16 = AxmlNode(
            tag = "provider",
            attributes = listOf(AxmlAttribute(null, "name", ".LegacyProvider", ".LegacyProvider", 0, 3, 0)),
            children = emptyList()
        )
        val app16 = AxmlNode(tag = "application", attributes = emptyList(), children = listOf(provNode16))
        val usesSdk16 = AxmlNode(tag = "uses-sdk", attributes = listOf(AxmlAttribute(null, "targetSdkVersion", "16", "16", 0, 16, 16)), children = emptyList())
        val manifest16 = AxmlNode(tag = "manifest", attributes = listOf(AxmlAttribute(null, "package", "com.example.test", "com.example.test", 0, 3, 0)), children = listOf(usesSdk16, app16))

        val surface16 = AttackSurfaceResolver(HardenedZipReader("test.apk", createEmptyZip()), manifest16, null).resolve()
        val p16 = surface16.components.first { it.name == "com.example.test.LegacyProvider" }
        assertThat(p16.exported).isTrue()
        assertThat(p16.exportStatus).isEqualTo(io.apkwarden.core.model.ExportStatus.IMPLICIT_EXPORTED)

        // Provider on targetSdk 17+ with no attribute -> default exported=false (even with intent-filter!)
        val dummyFilter = AxmlNode(tag = "intent-filter", attributes = emptyList(), children = emptyList())
        val provNode17 = AxmlNode(
            tag = "provider",
            attributes = listOf(AxmlAttribute(null, "name", ".ModernProvider", ".ModernProvider", 0, 3, 0)),
            children = listOf(dummyFilter)
        )
        val app17 = AxmlNode(tag = "application", attributes = emptyList(), children = listOf(provNode17))
        val usesSdk17 = AxmlNode(tag = "uses-sdk", attributes = listOf(AxmlAttribute(null, "targetSdkVersion", "17", "17", 0, 16, 17)), children = emptyList())
        val manifest17 = AxmlNode(tag = "manifest", attributes = listOf(AxmlAttribute(null, "package", "com.example.test", "com.example.test", 0, 3, 0)), children = listOf(usesSdk17, app17))

        val surface17 = AttackSurfaceResolver(HardenedZipReader("test.apk", createEmptyZip()), manifest17, null).resolve()
        val p17 = surface17.components.first { it.name == "com.example.test.ModernProvider" }
        assertThat(p17.exported).isFalse()
        assertThat(p17.exportStatus).isEqualTo(io.apkwarden.core.model.ExportStatus.NOT_EXPORTED)
    }

    @Test
    fun `inherits application level permission when component specifies none`() {
        val actNode = AxmlNode(
            tag = "activity",
            attributes = listOf(AxmlAttribute(null, "name", ".SecureActivity", null, 0, 3, 0)),
            children = emptyList()
        )
        val appNode = AxmlNode(
            tag = "application",
            attributes = listOf(AxmlAttribute(null, "permission", "com.example.APP_PERM", null, 0, 3, 0)),
            children = listOf(actNode)
        )
        val manifestNode = AxmlNode(
            tag = "manifest",
            attributes = listOf(AxmlAttribute(null, "package", "com.example.test", null, 0, 3, 0)),
            children = listOf(appNode)
        )

        val surface = AttackSurfaceResolver(HardenedZipReader("test.apk", createEmptyZip()), manifestNode, null).resolve()
        val act = surface.components.first { it.name == "com.example.test.SecureActivity" }
        assertThat(act.permission).isEqualTo("com.example.APP_PERM")
    }

    @Test
    fun `computes cartesian product of deep link data tags`() {
        val actionNode = AxmlNode(
            tag = "action",
            attributes = listOf(AxmlAttribute(null, "name", "android.intent.action.VIEW", null, 0, 3, 0)),
            children = emptyList()
        )
        val catBrowsable = AxmlNode(
            tag = "category",
            attributes = listOf(AxmlAttribute(null, "name", "android.intent.category.BROWSABLE", null, 0, 3, 0)),
            children = emptyList()
        )
        val dataScheme1 = AxmlNode(tag = "data", attributes = listOf(AxmlAttribute(null, "scheme", "https", null, 0, 3, 0)), children = emptyList())
        val dataScheme2 = AxmlNode(tag = "data", attributes = listOf(AxmlAttribute(null, "scheme", "myapp", null, 0, 3, 0)), children = emptyList())
        val dataHost1 = AxmlNode(tag = "data", attributes = listOf(AxmlAttribute(null, "host", "example.com", null, 0, 3, 0)), children = emptyList())
        val dataHost2 = AxmlNode(tag = "data", attributes = listOf(AxmlAttribute(null, "host", "api.example.com", null, 0, 3, 0)), children = emptyList())
        val dataPath1 = AxmlNode(tag = "data", attributes = listOf(AxmlAttribute(null, "path", "/checkout", null, 0, 3, 0)), children = emptyList())

        val filterNode = AxmlNode(
            tag = "intent-filter",
            attributes = listOf(AxmlAttribute(null, "autoVerify", "true", "true", 0, 0x12, 1)),
            children = listOf(actionNode, catBrowsable, dataScheme1, dataScheme2, dataHost1, dataHost2, dataPath1)
        )

        val activityNode = AxmlNode(
            tag = "activity",
            attributes = listOf(
                AxmlAttribute(null, "name", ".CheckoutActivity", null, 0, 3, 0),
                AxmlAttribute(null, "exported", "true", "true", 0, 0x12, 1)
            ),
            children = listOf(filterNode)
        )

        val appNode = AxmlNode(tag = "application", attributes = emptyList(), children = listOf(activityNode))
        val manifestNode = AxmlNode(
            tag = "manifest",
            attributes = listOf(AxmlAttribute(null, "package", "com.example.shop", null, 0, 3, 0)),
            children = listOf(appNode)
        )

        val dummyArchive = HardenedZipReader("test.apk", createEmptyZip())
        val surface = AttackSurfaceResolver(dummyArchive, manifestNode, null).resolve()

        // 2 schemes (https, myapp) x 2 hosts (example.com, api.example.com) x 1 path (/checkout) = 4 deep links!
        assertThat(surface.deepLinks).hasSize(4)
        assertThat(surface.deepLinks).anyMatch { it.scheme == "https" && it.host == "example.com" && it.path == "/checkout" && it.autoVerify }
        assertThat(surface.deepLinks).anyMatch { it.scheme == "myapp" && it.host == "api.example.com" && it.path == "/checkout" && !it.autoVerify }
    }

    private fun createEmptyZip(): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(byteArrayOf(0))
            zos.closeEntry()
        }
        return baos.toByteArray()
    }
}
