package io.apkwarden.core.fingerprint

import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.model.*
import io.apkwarden.core.parser.R8MarkerParser

object StackFingerprinter {

    private val PACKER_SIGNATURES = mapOf(
        "Qihoo 360 / Jiagu" to listOf("libjiagu.so", "libjiagu_a64.so", "assets/libjiagu.so"),
        "DexGuard" to listOf("assets/dexguard/", "assets/classes.dex.enc"),
        "Promon SHIELD" to listOf("libsec.so", "libpromon.so", "libpromon-native.so"),
        "SecNeo / DexHelper" to listOf("libSecShell.so", "libDexHelper.so", "libSecShell-x86.so"),
        "Bangcle / SecShell" to listOf("libsecexe.so", "libsecmain.so", "assets/bangcleplugin/"),
        "Tencent Legu" to listOf("libshell.so", "libtxcore.so", "libshella-"),
        "Baidu Protect" to listOf("libbaiduprotect.so", "libbaiduprotect_x86.so"),
        "Ali / IJiami" to listOf("libexec.so", "libexecmain.so", "ijiami.dat")
    )

    fun fingerprint(archive: ApkArchive, dexBytesList: List<ByteArray>): StackFingerprint {
        val entries = archive.listEntries()

        // 1. Packer check
        val packer = detectPacker(entries)

        // 2. Stack check
        val detectedStacks = mutableListOf<RuntimeStack>()

        val hasFlutter = entries.any { it.contains("libflutter.so") || it.contains("libapp.so") || it.startsWith("assets/flutter_assets") }
        if (hasFlutter) detectedStacks.add(RuntimeStack.FLUTTER)

        val bundleEntry = archive.getEntryBytes("assets/index.android.bundle")
        val hasHermesLib = entries.any { it.contains("libhermes.so") }
        val isHermesBytecode = bundleEntry != null && isHermesMagic(bundleEntry)
        if (isHermesBytecode || hasHermesLib) {
            detectedStacks.add(RuntimeStack.REACT_NATIVE_HERMES)
        } else if (bundleEntry != null || entries.any { it.contains("libjsc.so") }) {
            detectedStacks.add(RuntimeStack.REACT_NATIVE_JSC)
        }

        val hasCordova = entries.any { it.contains("assets/www/index.html") || it.contains("cordova.js") || it.contains("capacitor.js") }
        if (hasCordova) detectedStacks.add(RuntimeStack.CORDOVA_CAPACITOR)

        val hasXamarin = entries.any { it.contains("libmonodroid.so") || it.contains("assemblies/") || it.contains("libxamarin-app.so") }
        if (hasXamarin) detectedStacks.add(RuntimeStack.XAMARIN_MAUI)

        val hasUnityIl2cpp = entries.any { it.contains("libil2cpp.so") }
        val hasUnityMono = entries.any { it.contains("libmono.so") && it.contains("assets/bin/Data") }
        if (hasUnityIl2cpp) detectedStacks.add(RuntimeStack.UNITY_IL2CPP)
        if (hasUnityMono) detectedStacks.add(RuntimeStack.UNITY_MONO)

        val nativeSoFiles = entries.filter { it.startsWith("lib/") && it.endsWith(".so") }
        if (nativeSoFiles.size > 3 && detectedStacks.isEmpty()) {
            detectedStacks.add(RuntimeStack.NATIVE_NDK_HEAVY)
        }

        val primaryStack = detectedStacks.firstOrNull() ?: RuntimeStack.PURE_DEX

        // 3. Compiler Marker (R8 / D8)
        val marker = dexBytesList.firstNotNullOfOrNull { R8MarkerParser.extractMarker(it) }

        // 4. Native Libraries info
        val nativeLibraries = inspectNativeLibraries(archive, nativeSoFiles)

        // 5. Coverage Statement
        val coverage = buildCoverageStatement(primaryStack, packer, nativeLibraries)

        return StackFingerprint(
            primaryStack = primaryStack,
            detectedStacks = detectedStacks,
            packer = packer,
            compilerMarker = marker,
            nativeLibraries = nativeLibraries,
            coverageStatement = coverage
        )
    }

    private fun detectPacker(entries: List<String>): PackerDetection {
        for ((packerName, signatures) in PACKER_SIGNATURES) {
            for (sig in signatures) {
                val matched = entries.firstOrNull { it.contains(sig) }
                if (matched != null) {
                    return PackerDetection(
                        detected = true,
                        packerName = packerName,
                        signatureFound = matched,
                        confidence = "HIGH"
                    )
                }
            }
        }
        return PackerDetection(detected = false)
    }

    private fun isHermesMagic(bytes: ByteArray): Boolean {
        if (bytes.size < 4) return false
        // Hermes magic: 0x1FBC03C6 (little endian bytes: C6 03 BC 1F)
        return bytes[0] == 0xC6.toByte() && bytes[1] == 0x03.toByte() && bytes[2] == 0xBC.toByte() && bytes[3] == 0x1F.toByte()
    }

    private fun inspectNativeLibraries(archive: ApkArchive, soEntries: List<String>): List<NativeLibraryInfo> {
        val result = mutableListOf<NativeLibraryInfo>()

        for (path in soEntries) {
            val parts = path.split("/")
            if (parts.size >= 3) {
                val abi = parts[1]
                val name = parts.last()

                // Check version strings inside the .so file
                val bytes = archive.getEntryBytes(path) ?: continue
                val versionStrings = scanLibraryVersions(bytes)
                val is16k = check16KbAlignment(bytes)
                val hasFullRelro = checkFullRelro(bytes)

                result.add(
                    NativeLibraryInfo(
                        name = name,
                        abi = abi,
                        is16KbAligned = is16k,
                        hasFullRelro = hasFullRelro,
                        detectedVersionStrings = versionStrings
                    )
                )
            }
        }

        return result
    }

    private fun scanLibraryVersions(bytes: ByteArray): List<String> {
        val text = String(bytes, Charsets.ISO_8859_1)
        val versions = mutableListOf<String>()

        val patterns = listOf(
            Regex("""OpenSSL\s+([0-9]+\.[0-9]+\.[0-9]+[a-z]?)"""),
            Regex("""sqlite[_\s]+([0-9]+\.[0-9]+\.[0-9]+)"""),
            Regex("""libpng\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)"""),
            Regex("""zlib\s+version\s+([0-9]+\.[0-9]+\.[0-9]+)"""),
            Regex("""FFmpeg\s+version\s+([0-9]+\.[0-9]+)""")
        )

        for (pattern in patterns) {
            pattern.find(text)?.let {
                versions.add(it.value)
            }
        }

        return versions
    }

    private fun check16KbAlignment(bytes: ByteArray): Boolean? {
        if (bytes.size < 64) return null
        // Basic ELF header check
        if (bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()) {
            return null
        }
        val is64Bit = bytes[4] == 2.toByte()
        // In 64-bit ELF, program header table offset e_phoff is at offset 32 (8 bytes), e_phnum is at offset 56 (2 bytes)
        if (!is64Bit || bytes.size < 64) return true // default pass for 32-bit or small stubs

        val phtOffset = readLongLE(bytes, 32)
        val phCount = readShortLE(bytes, 56)
        val phEntrySize = readShortLE(bytes, 54)

        var aligned = true
        for (i in 0 until phCount) {
            val phPos = (phtOffset + i * phEntrySize).toInt()
            if (phPos + 56 > bytes.size) break

            val pType = readIntLE(bytes, phPos)
            if (pType == 1) { // PT_LOAD
                val pAlign = readLongLE(bytes, phPos + 48)
                if (pAlign < 16384) { // Less than 16 KB (0x4000)
                    aligned = false
                }
            }
        }
        return aligned
    }

    private fun checkFullRelro(bytes: ByteArray): Boolean? {
        if (bytes.size < 64) return null
        val text = String(bytes, Charsets.ISO_8859_1)
        // Check for GNU_RELRO segment indicator or BIND_NOW
        return text.contains("BIND_NOW") || text.contains(".relro")
    }

    private fun readIntLE(b: ByteArray, offset: Int): Int {
        return (b[offset].toInt() and 0xFF) or
                ((b[offset + 1].toInt() and 0xFF) shl 8) or
                ((b[offset + 2].toInt() and 0xFF) shl 16) or
                ((b[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun readShortLE(b: ByteArray, offset: Int): Int {
        return (b[offset].toInt() and 0xFF) or ((b[offset + 1].toInt() and 0xFF) shl 8)
    }

    private fun readLongLE(b: ByteArray, offset: Int): Long {
        var res = 0L
        for (i in 0 until 8) {
            res = res or ((b[offset + i].toLong() and 0xFFL) shl (i * 8))
        }
        return res
    }

    private fun buildCoverageStatement(
        stack: RuntimeStack,
        packer: PackerDetection,
        nativeLibs: List<NativeLibraryInfo>
    ): CoverageStatement {
        val blindSpots = mutableListOf<String>()
        val notes = mutableListOf<String>()

        val isPacked = packer.detected
        val dexCoverage = when {
            isPacked -> {
                blindSpots.add("App is packed by ${packer.packerName}. Static DEX bytecode is an encrypted stub; coverage is limited to Manifest and exported attack surface.")
                5
            }
            stack == RuntimeStack.FLUTTER -> {
                blindSpots.add("Flutter AOT runtime detected. Core business logic is compiled to Dart assembly inside libapp.so; Dalvik DEX analysis only covers the Android host shell.")
                15
            }
            stack == RuntimeStack.REACT_NATIVE_HERMES -> {
                blindSpots.add("React Native Hermes bytecode detected. JavaScript logic is compiled to index.android.bundle; Dalvik DEX analysis covers native host modules only.")
                25
            }
            stack == RuntimeStack.UNITY_IL2CPP -> {
                blindSpots.add("Unity IL2CPP game engine detected. Game logic resides in libil2cpp.so; Dalvik DEX analysis only covers splash and bridge activities.")
                10
            }
            else -> {
                notes.add("Standard Dalvik bytecode analysis: full static coverage of Java/Kotlin components.")
                95
            }
        }

        return CoverageStatement(
            primaryStack = stack,
            isPacked = isPacked,
            packerName = packer.packerName,
            dexCoveragePct = dexCoverage,
            nativeCodePresent = nativeLibs.isNotEmpty(),
            nativeLibraryCount = nativeLibs.size,
            blindSpots = blindSpots,
            notes = notes
        )
    }
}
