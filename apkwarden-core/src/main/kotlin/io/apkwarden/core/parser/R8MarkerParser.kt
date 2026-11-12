package io.apkwarden.core.parser

import io.apkwarden.core.model.CompilerMarker

object R8MarkerParser {

    private val R8_MARKER_REGEX = Regex("""~~R8\{([^}]+)\}""")
    private val D8_MARKER_REGEX = Regex("""~~D8\{([^}]+)\}""")

    fun extractMarker(dexBytes: ByteArray): CompilerMarker? {
        val dexString = String(dexBytes, Charsets.ISO_8859_1)

        val r8Match = R8_MARKER_REGEX.find(dexString)
        if (r8Match != null) {
            val content = r8Match.groupValues[1]
            return parseProperties("R8", content)
        }

        val d8Match = D8_MARKER_REGEX.find(dexString)
        if (d8Match != null) {
            val content = d8Match.groupValues[1]
            return parseProperties("D8", content)
        }

        return null
    }

    private fun parseProperties(compiler: String, content: String): CompilerMarker {
        val pairs = content.split(",").associate {
            val idx = it.indexOf(':')
            if (idx > 0) {
                it.substring(0, idx).trim() to it.substring(idx + 1).trim()
            } else {
                it.trim() to ""
            }
        }

        val version = pairs["version"]
        val minApi = pairs["min-api"]?.toIntOrNull()
        val isFullMode = pairs["compilation-mode"] == "release" || pairs["is-compat"] == "false"
        val pgMapId = pairs["pg-map-id"]

        return CompilerMarker(
            compiler = compiler,
            version = version,
            minApi = minApi,
            isFullMode = isFullMode,
            pgMapId = pgMapId
        )
    }

    fun verifyMappingId(marker: CompilerMarker?, mappingFileContent: String): Boolean {
        val expectedId = marker?.pgMapId ?: return true // no marker to verify against
        // Check if pg-map-id appears in the mapping file header
        return mappingFileContent.contains(expectedId)
    }
}
