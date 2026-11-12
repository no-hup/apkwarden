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
