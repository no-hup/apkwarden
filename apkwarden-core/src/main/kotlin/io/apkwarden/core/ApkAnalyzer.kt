package io.apkwarden.core

import io.apkwarden.core.fingerprint.StackFingerprinter
import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.ingest.ApkIngestManager
import io.apkwarden.core.lock.SurfaceLockGenerator
import io.apkwarden.core.model.AttackSurface
import io.apkwarden.core.model.StackFingerprint
import io.apkwarden.core.model.SurfaceLock
import io.apkwarden.core.parser.ArscParser
import io.apkwarden.core.parser.AxmlParser
import io.apkwarden.core.surface.AttackSurfaceResolver
import java.io.File

data class AnalysisResult(
    val archiveName: String,
    val isSplitSet: Boolean,
    val isAab: Boolean,
    val attackSurface: AttackSurface,
    val fingerprint: StackFingerprint,
    val surfaceLock: SurfaceLock,
    val warnings: List<String> = emptyList()
)

object ApkAnalyzer {

    fun analyze(file: File): AnalysisResult {
        return ApkIngestManager.open(file).use { analyzeArchive(it) }
    }

    fun analyzeArchive(arch: ApkArchive): AnalysisResult {
        val warnings = mutableListOf<String>()

            // Check ZIP anomalies
            for (anomaly in arch.getAnomalies()) {
                warnings.add("[${anomaly.type}] ${anomaly.entryName}: ${anomaly.description}")
            }

            // Manifest parsing
            val manifestBytes = arch.getEntryBytes("AndroidManifest.xml")
                ?: throw IllegalArgumentException("APK/AAB does not contain AndroidManifest.xml")

            val manifestNode = AxmlParser(manifestBytes).parse()

            // Resource table parsing
            val arscBytes = arch.getEntryBytes("resources.arsc")
            val arscParser = if (arscBytes != null) ArscParser(arscBytes).also { it.parse() } else null

            // DEX files
            val dexEntries = arch.listEntries().filter { it.startsWith("classes") && it.endsWith(".dex") }
            val dexBytesList = dexEntries.mapNotNull { arch.getEntryBytes(it) }

            // Stack & Protection Fingerprinting
            val fingerprint = StackFingerprinter.fingerprint(arch, dexBytesList)

            // Attack surface resolution
            val surfaceResolver = AttackSurfaceResolver(arch, manifestNode, arscParser)
            val attackSurface = surfaceResolver.resolve()

            // Check lone base.apk split warnings
            val isSplitRequired = manifestNode.findAttribute("isSplitRequired")?.booleanValue ?: false
            if (isSplitRequired && !arch.isSplitSet) {
                warnings.add(
                    "[SPLIT_WARNING] The manifest specifies 'isSplitRequired=true', but this scan was run on a single base APK without its accompanying config splits. Native libraries and split resources may be absent."
                )
            }

            // Lock generation
            val surfaceLock = SurfaceLockGenerator.generate(attackSurface, fingerprint)

        return AnalysisResult(
            archiveName = arch.archiveName,
            isSplitSet = arch.isSplitSet,
            isAab = arch.isAab,
            attackSurface = attackSurface,
            fingerprint = fingerprint,
            surfaceLock = surfaceLock,
            warnings = warnings
        )
    }

    fun scan(file: File, rules: List<io.apkwarden.core.rules.Rule> = io.apkwarden.core.rules.RuleRegistry.allRules): io.apkwarden.core.model.ScanReport {
        val archive = ApkIngestManager.open(file)
        return archive.use {
            io.apkwarden.core.scan.ScanEngine(rules).scan(it)
        }
    }
}
