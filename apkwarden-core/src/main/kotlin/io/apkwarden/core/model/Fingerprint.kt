package io.apkwarden.core.model

import kotlinx.serialization.Serializable

@Serializable
enum class RuntimeStack {
    PURE_DEX,
    FLUTTER,
    REACT_NATIVE_HERMES,
    REACT_NATIVE_JSC,
    CORDOVA_CAPACITOR,
    XAMARIN_MAUI,
    UNITY_IL2CPP,
    UNITY_MONO,
    NATIVE_NDK_HEAVY,
    UNKNOWN
}

@Serializable
data class PackerDetection(
    val detected: Boolean,
    val packerName: String? = null,
    val signatureFound: String? = null,
    val confidence: String = "HIGH"
)

@Serializable
data class CompilerMarker(
    val compiler: String, // "R8" or "D8" or "UNKNOWN"
    val version: String? = null,
    val minApi: Int? = null,
    val isFullMode: Boolean = false,
    val pgMapId: String? = null
)

@Serializable
data class NativeLibraryInfo(
    val name: String,
    val abi: String,
    val is16KbAligned: Boolean? = null,
    val hasFullRelro: Boolean? = null,
    val hasExecutableStack: Boolean? = null,
    val detectedVersionStrings: List<String> = emptyList()
)

@Serializable
data class CoverageStatement(
    val primaryStack: RuntimeStack,
    val isPacked: Boolean,
    val packerName: String?,
    val dexCoveragePct: Int, // 0 to 100
    val nativeCodePresent: Boolean,
    val nativeLibraryCount: Int,
    val blindSpots: List<String> = emptyList(),
    val notes: List<String> = emptyList()
)

@Serializable
data class StackFingerprint(
    val primaryStack: RuntimeStack,
    val detectedStacks: List<RuntimeStack> = emptyList(),
    val packer: PackerDetection,
    val compilerMarker: CompilerMarker?,
    val nativeLibraries: List<NativeLibraryInfo> = emptyList(),
    val coverageStatement: CoverageStatement
)
