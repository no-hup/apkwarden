package io.apkwarden.core.scan

import io.apkwarden.core.dex.DexIndex
import io.apkwarden.core.fingerprint.StackFingerprinter
import io.apkwarden.core.ingest.ApkArchive
import io.apkwarden.core.model.*
import io.apkwarden.core.parser.ArscParser
import io.apkwarden.core.parser.AxmlParser
import io.apkwarden.core.rules.AnalysisContext
import io.apkwarden.core.rules.Rule
import io.apkwarden.core.rules.RuleRegistry
import io.apkwarden.core.surface.AttackSurfaceResolver
import java.time.Instant

class ScanEngine(private val rules: List<Rule> = RuleRegistry.allRules) {

    fun scan(archive: ApkArchive): ScanReport {
        // 1. Parse manifest
        val manifestBytes = archive.getEntryBytes("AndroidManifest.xml")
            ?: throw IllegalArgumentException("Missing AndroidManifest.xml in ${archive.archiveName}")
        val manifestNode = AxmlParser(manifestBytes).parse()

        // 2. Parse ARSC if available
        val arscBytes = archive.getEntryBytes("resources.arsc")
        val arscParser = arscBytes?.let { ArscParser(it) }

        // 3. Resolve Attack Surface
        val surface = AttackSurfaceResolver(archive, manifestNode, arscParser).resolve()

        // 4. Fingerprint stack & packers
        val dexEntries = archive.listEntries().filter { entry ->
            entry.endsWith(".dex") && (entry.startsWith("classes") || entry.contains("/dex/classes") || entry == "classes.dex")
        }
        val dexBytesList = dexEntries.mapNotNull { archive.getEntryBytes(it) }
        val fingerprint = StackFingerprinter.fingerprint(archive, dexBytesList)

        // 5. Index DEX bytecode
        val dexIndex = DexIndex.build(archive)

        // 6. Run Rules Engine
        val context = AnalysisContext(
            archive = archive,
            attackSurface = surface,
            stackFingerprint = fingerprint,
            dexIndex = dexIndex
        )

        val findings = mutableListOf<Finding>()
        for (rule in rules) {
            findings.addAll(rule.analyze(context))
        }

        // 7. Calculate Summary & Security Score
        val criticalCount = findings.count { it.severity == Severity.CRITICAL }
        val highCount = findings.count { it.severity == Severity.HIGH }
        val mediumCount = findings.count { it.severity == Severity.MEDIUM }
        val lowCount = findings.count { it.severity == Severity.LOW }
        val infoCount = findings.count { it.severity == Severity.INFO }

        // Warnings collection
        val scanWarnings = mutableListOf<String>()
        scanWarnings.addAll(dexIndex.parsingErrors)
        if (fingerprint.packer.detected) {
            scanWarnings.add("PACKER DETECTED: Commercial protector '${fingerprint.packer.packerName}' detected. Bytecode analysis has reduced visibility (${fingerprint.coverageStatement.dexCoveragePct}% coverage).")
        }
        scanWarnings.addAll(fingerprint.coverageStatement.blindSpots)

        // Security score formula: Starts at 100, penalizes by severity
        val penalty = (criticalCount * 25) + (highCount * 15) + (mediumCount * 5) + (lowCount * 2)
        val score = maxOf(0, 100 - penalty)

        val summary = ScanSummary(
            totalFindings = findings.size,
            criticalCount = criticalCount,
            highCount = highCount,
            mediumCount = mediumCount,
            lowCount = lowCount,
            infoCount = infoCount,
            securityScore = score
        )

        return ScanReport(
            apkName = archive.archiveName,
            scanTimestamp = Instant.now().toString(),
            attackSurface = surface,
            stackFingerprint = fingerprint,
            findings = findings.sortedWith(compareBy({ it.severity }, { it.id })),
            summary = summary,
            scanWarnings = scanWarnings
        )
    }
}
