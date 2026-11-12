package io.apkwarden.core.parser

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream

class ProtoXmlDecoderTest {

    private fun writeVarint(out: ByteArrayOutputStream, value: Long) {
        var v = value
        while (v and 0x7FL.inv() != 0L) {
            out.write(((v and 0x7F) or 0x80).toInt())
            v = v ushr 7
        }
        out.write((v and 0x7F).toInt())
    }

    private fun writeField(out: ByteArrayOutputStream, fieldNum: Int, wireType: Int, data: ByteArray) {
        val tag = (fieldNum shl 3) or wireType
        writeVarint(out, tag.toLong())
        if (wireType == 2) {
            writeVarint(out, data.size.toLong())
        }
        out.write(data)
    }

    private fun writeStringField(out: ByteArrayOutputStream, fieldNum: Int, str: String) {
        writeField(out, fieldNum, 2, str.toByteArray(Charsets.UTF_8))
    }

    private fun writeVarintField(out: ByteArrayOutputStream, fieldNum: Int, value: Long) {
        val tag = (fieldNum shl 3) or 0
        writeVarint(out, tag.toLong())
        writeVarint(out, value)
    }

    @Test
    fun `decodes AAPT2 protobuf XmlNode into AxmlNode tree`() {
        // Attribute 1: android:debuggable="true" (resId: 0x0101000f)
        val attr1Stream = ByteArrayOutputStream()
        writeStringField(attr1Stream, 1, "http://schemas.android.com/apk/res/android")
        writeStringField(attr1Stream, 2, "debuggable")
        writeStringField(attr1Stream, 3, "true")
        writeVarintField(attr1Stream, 5, 0x0101000f)

        // Child Element: <application debuggable="true">
        val appElemStream = ByteArrayOutputStream()
        writeStringField(appElemStream, 3, "application")
        writeField(appElemStream, 4, 2, attr1Stream.toByteArray())

        // Child XmlNode
        val childNodeStream = ByteArrayOutputStream()
        writeField(childNodeStream, 2, 2, appElemStream.toByteArray())

        // Root Element: <manifest package="com.example.protoapp">
        val rootAttrStream = ByteArrayOutputStream()
        writeStringField(rootAttrStream, 2, "package")
        writeStringField(rootAttrStream, 3, "com.example.protoapp")

        val rootElemStream = ByteArrayOutputStream()
        writeStringField(rootElemStream, 3, "manifest")
        writeField(rootElemStream, 4, 2, rootAttrStream.toByteArray())
        writeField(rootElemStream, 5, 2, childNodeStream.toByteArray())

        // Root XmlNode
        val rootNodeStream = ByteArrayOutputStream()
        writeField(rootNodeStream, 2, 2, rootElemStream.toByteArray())

        val protoBytes = rootNodeStream.toByteArray()

        // Decode using ProtoXmlDecoder and AxmlParser
        val node = AxmlParser(protoBytes).parse()

        assertThat(node.tag).isEqualTo("manifest")
        val pkgAttr = node.findAttribute("package")
        assertThat(pkgAttr).isNotNull
        assertThat(pkgAttr!!.value).isEqualTo("com.example.protoapp")

        val appNode = node.findChildren("application").firstOrNull()
        assertThat(appNode).isNotNull
        val debugAttr = appNode!!.findAttribute("debuggable")
        assertThat(debugAttr).isNotNull
        assertThat(debugAttr!!.booleanValue).isTrue()
        assertThat(debugAttr.resourceId).isEqualTo(0x0101000f)
    }
}
