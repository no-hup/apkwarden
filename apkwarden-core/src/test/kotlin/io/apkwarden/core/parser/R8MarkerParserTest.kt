package io.apkwarden.core.parser

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class R8MarkerParserTest {

    @Test
    fun `extracts R8 marker properties correctly`() {
        val dexContent = "prefix padding ~~R8{backend:dex,compilation-mode:release,min-api:24,pg-map-id:7a28be48a91c,version:8.2.33} suffix padding"
        val marker = R8MarkerParser.extractMarker(dexContent.toByteArray(Charsets.ISO_8859_1))

        assertThat(marker).isNotNull
        assertThat(marker?.compiler).isEqualTo("R8")
        assertThat(marker?.version).isEqualTo("8.2.33")
        assertThat(marker?.minApi).isEqualTo(24)
        assertThat(marker?.isFullMode).isTrue()
        assertThat(marker?.pgMapId).isEqualTo("7a28be48a91c")
    }

    @Test
    fun `extracts D8 marker properties correctly`() {
        val dexContent = "~~D8{backend:dex,min-api:21,version:8.0.12}"
        val marker = R8MarkerParser.extractMarker(dexContent.toByteArray(Charsets.ISO_8859_1))

        assertThat(marker).isNotNull
        assertThat(marker?.compiler).isEqualTo("D8")
        assertThat(marker?.version).isEqualTo("8.0.12")
        assertThat(marker?.minApi).isEqualTo(21)
    }

    @Test
    fun `verifies mapping id match`() {
        val marker = R8MarkerParser.extractMarker("~~R8{pg-map-id:abc123hash}".toByteArray())
        val matchingMapping = "# pg-map-id: abc123hash\ncom.example.Foo -> a.a:\n"
        val mismatchMapping = "# pg-map-id: wronghash\ncom.example.Foo -> a.a:\n"

        assertThat(R8MarkerParser.verifyMappingId(marker, matchingMapping)).isTrue()
        assertThat(R8MarkerParser.verifyMappingId(marker, mismatchMapping)).isFalse()
    }
}
