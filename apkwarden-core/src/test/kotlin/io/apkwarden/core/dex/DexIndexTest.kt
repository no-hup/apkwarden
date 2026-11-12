package io.apkwarden.core.dex

import io.apkwarden.core.ingest.HardenedZipReader
import io.apkwarden.core.testutil.SmaliDexBuilder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class DexIndexTest {

    @Test
    fun `indexes classes and resolves virtual hierarchy correctly`() {
        val smali = """
            .class public Lcom/example/MyCustomWebView;
            .super Landroid/webkit/WebView;
            .source "MyCustomWebView.java"
            
            .method public constructor <init>()V
                .registers 1
                invoke-direct {p0}, Landroid/webkit/WebView;-><init>()V
                return-void
            .end method
            
            .method public testLoad(Ljava/lang/String;)V
                .registers 2
                invoke-virtual {p0, p1}, Lcom/example/MyCustomWebView;->loadUrl(Ljava/lang/String;)V
                return-void
            .end method
        """.trimIndent()

        val dexBytes = SmaliDexBuilder.assemble(smali)
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(dexBytes)
            zos.closeEntry()
        }

        val archive = HardenedZipReader("test.apk", baos.toByteArray())
        val index = DexIndex.build(archive)

        assertThat(index.classDefs).containsKey("com.example.MyCustomWebView")
        assertThat(index.hierarchy.isSubclassOf("com.example.MyCustomWebView", "android.webkit.WebView")).isTrue()
        assertThat(index.hierarchy.isSubclassOf("com.example.MyCustomWebView", "android.view.View")).isTrue()

        // Test call site resolution via virtual dispatch
        val callSites = index.findCallSites("android.webkit.WebView", "loadUrl")
        assertThat(callSites).hasSize(1)
        assertThat(callSites[0].callerClass).isEqualTo("com.example.MyCustomWebView")
        assertThat(callSites[0].callerMethod).isEqualTo("testLoad")
    }
}
