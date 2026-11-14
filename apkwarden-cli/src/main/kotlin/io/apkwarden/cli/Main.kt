package io.apkwarden.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.multiple
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.versionOption
import com.github.ajalt.clikt.parameters.types.file
import io.apkwarden.core.ApkAnalyzer
import io.apkwarden.core.baseline.BaselineEngine
import io.apkwarden.core.diff.DiffSeverity
import io.apkwarden.core.diff.SurfaceDiffEngine
import io.apkwarden.core.diff.SurfaceDiffResult
import io.apkwarden.core.lock.SurfaceLockGenerator
import io.apkwarden.core.model.Confidence
import io.apkwarden.core.model.Finding
import io.apkwarden.core.model.FindingOwner
import io.apkwarden.core.model.Reachability
import io.apkwarden.core.model.ScanReport
import io.apkwarden.core.model.Severity
import io.apkwarden.core.model.SurfaceLock
import io.apkwarden.core.sarif.SarifSerializer
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File

class ApkwardenCli : CliktCommand(name = "apkwarden") {
    init {
        versionOption("0.1.0")
    }
    override fun help(context: Context): String = "APKwarden: Fast, reachability-first Android security analyzer."
    override fun run() = Unit
}

class SurfaceCommand : CliktCommand(name = "surface") {
    override fun help(context: Context): String = "Analyze and display the resolved attack surface of an APK, split cluster, or AAB."

    private val target by argument("apk-file", help = "Path to APK, AAB, split directory, or .apks bundle").file(mustExist = true)

    override fun run() {
        echo("Analyzing attack surface: ${target.name}...")
        val result = ApkAnalyzer.analyze(target)
        val surface = result.attackSurface

        echo("")
        echo("=== PACKAGE SUMMARY ===")
        echo("Package:         ${surface.packageName}")
        echo("Version:         ${surface.versionName ?: "N/A"} (${surface.versionCode})")
        echo("SDK Range:       minSdk=${surface.minSdk}, targetSdk=${surface.targetSdk}")
        echo("Debuggable:      ${surface.isDebuggable}")
        echo("Allow Backup:    ${surface.allowBackup}")
        echo("Archive Format:  ${if (result.isAab) "AAB" else if (result.isSplitSet) "Split Cluster" else "Standalone APK"}")

        if (result.warnings.isNotEmpty()) {
            echo("")
            echo("=== INGEST WARNINGS ===")
            result.warnings.forEach { echo("⚠️  $it") }
        }

        echo("")
        echo("=== EXPORTED ATTACK SURFACE (${surface.exportedComponents.size} components) ===")
        if (surface.exportedComponents.isEmpty()) {
            echo("No exported components found.")
        } else {
            surface.exportedComponents.forEach { comp ->
                val permStr = when {
                    comp.permission != null -> " [Guarded by: ${comp.permission}]"
                    comp.readPermission != null || comp.writePermission != null -> " [Read: ${comp.readPermission ?: "none"}, Write: ${comp.writePermission ?: "none"}]"
                    else -> " ⚠️ UNGUARDED"
                }
                echo("• [${comp.type}] ${comp.name}$permStr")
            }
        }

        if (surface.deepLinks.isNotEmpty()) {
            echo("")
            echo("=== DEEP LINKS (${surface.deepLinks.size} patterns) ===")
            surface.deepLinks.forEach { link ->
                val autoVerifyStr = if (link.autoVerify) " (App Link / autoVerify=true)" else ""
                val hostStr = if (link.host != null) "://${link.host}" else "://"
                val pathStr = link.path ?: ""
                echo("• ${link.scheme}$hostStr$pathStr -> ${link.targetComponent}$autoVerifyStr")
            }
        }

        if (surface.fileProviderPaths.isNotEmpty()) {
            echo("")
            echo("=== FILE PROVIDER PATHS (${surface.fileProviderPaths.size} paths) ===")
            surface.fileProviderPaths.forEach { fp ->
                val warn = if (fp.isRootPath) " 🚨 CRITICAL (root-path exposed)" else if (fp.isBroadWildcard) " ⚠️ BROAD WILDCARD" else ""
                echo("• <${fp.tag} name=\"${fp.name}\" path=\"${fp.path}\">$warn")
            }
        }

        val nsc = surface.networkSecurityConfig
        if (nsc != null) {
            echo("")
            echo("=== NETWORK SECURITY CONFIG ===")
            echo("Base Cleartext Permitted: ${nsc.baseCleartextPermitted}")
            echo("Trusts User Certs:        ${nsc.trustUserCertsGlobally}")
            nsc.domainConfigs.forEach { dc ->
                val pins = if (dc.certificatePins.isNotEmpty()) " (Pinned: ${dc.certificatePins.size} pins)" else ""
                echo("• ${dc.domain}: cleartext=${dc.cleartextPermitted}, trustUserCerts=${dc.trustUserCerts}$pins")
            }
        }
    }
}

class LockCommand : CliktCommand(name = "lock") {
    override fun help(context: Context): String = "Generate a deterministic surface.lock.json file to commit to git for PR security diffs."

    private val target by argument("apk-file", help = "Path to APK, AAB, or split cluster").file(mustExist = true)
    private val output by option("-o", "--output", help = "Output lockfile destination").default("surface.lock.json")

    override fun run() {
        val result = ApkAnalyzer.analyze(target)
        val jsonStr = SurfaceLockGenerator.serialize(result.surfaceLock)
        val outFile = File(output)
        outFile.writeText(jsonStr)
        echo("✓ Generated surface lockfile: ${outFile.absolutePath} (SHA256: ${result.surfaceLock.sha256Fingerprint.take(12)}...)")
    }
}

class FingerprintCommand : CliktCommand(name = "fingerprint") {
    override fun help(context: Context): String = "Inspect build compilers, packers, native libraries, and blind spots."

    private val target by argument("apk-file", help = "Path to APK or AAB").file(mustExist = true)

    override fun run() {
        val result = ApkAnalyzer.analyze(target)
        val fp = result.fingerprint
        val cov = fp.coverageStatement

        echo("=== STACK FINGERPRINT: ${target.name} ===")
        echo("Primary Runtime:     ${fp.primaryStack}")
        echo("Detected Runtimes:   ${fp.detectedStacks.joinToString(", ").ifEmpty { "PURE_DEX" }}")

        echo("")
        echo("=== PACKER & PROTECTOR ===")
        if (fp.packer.detected) {
            echo("🚨 PACKER DETECTED:   ${fp.packer.packerName}")
            echo("Signature:           ${fp.packer.signatureFound}")
            echo("Confidence:          ${fp.packer.confidence}")
        } else {
            echo("No known commercial packer or shell detected.")
        }

        echo("")
        echo("=== COMPILER & OBFUSCATION ===")
        val cm = fp.compilerMarker
        if (cm != null) {
            echo("Compiler:            ${cm.compiler} ${cm.version ?: ""}")
            echo("Compilation Mode:    ${if (cm.isFullMode) "R8 Full Mode" else "Compat / D8"}")
            echo("Min API:             ${cm.minApi ?: "N/A"}")
            echo("PG Map ID:           ${cm.pgMapId ?: "None"}")
        } else {
            echo("No R8/D8 marker embedded in DEX string table.")
        }

        if (fp.nativeLibraries.isNotEmpty()) {
            echo("")
            echo("=== NATIVE LIBRARIES (${fp.nativeLibraries.size} files) ===")
            fp.nativeLibraries.forEach { lib ->
                val alignStr = when (lib.is16KbAligned) {
                    true -> "✓ 16KB Aligned"
                    false -> "⚠️ NOT 16KB Aligned (Google Play warning)"
                    null -> "N/A"
                }
                val versions = if (lib.detectedVersionStrings.isNotEmpty()) " [${lib.detectedVersionStrings.joinToString(", ")}]" else ""
                echo("• ${lib.name} (${lib.abi}): $alignStr$versions")
            }
        }

        echo("")
        echo("=== COVERAGE & BLIND-SPOT STATEMENT ===")
        echo("DEX Static Coverage: ${cov.dexCoveragePct}%")
        cov.notes.forEach { echo("ℹ️  $it") }
        cov.blindSpots.forEach { echo("⚠️  $it") }
    }
}

class IngestCheckCommand : CliktCommand(name = "ingest-check") {
    override fun help(context: Context): String = "Verify zip integrity, path traversal safety, and split configuration."

    private val target by argument("apk-file", help = "Path to APK or split bundle").file(mustExist = true)

    override fun run() {
        val result = ApkAnalyzer.analyze(target)
        echo("=== INGEST INTEGRITY CHECK: ${target.name} ===")
        echo("Archive Type: ${if (result.isAab) "AAB (Android App Bundle)" else if (result.isSplitSet) "Split APK Cluster" else "Standalone APK"}")

        if (result.warnings.isEmpty()) {
            echo("✓ Clean archive: Zero ZIP anomalies or integrity violations detected.")
        } else {
            echo("⚠️  Archive Warnings / Anomalies:")
            result.warnings.forEach { echo("  • $it") }
        }
    }
}

class DiffCommand : CliktCommand(name = "diff") {
    override fun help(context: Context): String = "Compare attack surface between a baseline surface.lock.json and a new APK/AAB build."

    private val headTarget by argument("head", help = "Path to new APK, AAB, or surface.lock.json").file(mustExist = true)
    private val baseTarget by option("-b", "--baseline", help = "Path to baseline surface.lock.json (default: surface.lock.json in current directory)").file(mustExist = true)
    private val gitRef by option("--git-ref", help = "Git reference to baseline lockfile from base branch (e.g. origin/main:surface.lock.json)")
    private val jsonOutput by option("--json", help = "Output diff as JSON").flag(default = false)
    private val failOnBreaking by option(
        "--fail-on-breaking",
        help = "Exit with code 2 if breaking attack surface additions are detected"
    ).flag("--no-fail-on-breaking", default = true)

    private val json = Json { prettyPrint = true }

    override fun run() {
        val baseLock = when {
            gitRef != null -> {
                try {
                    val proc = ProcessBuilder("git", "show", gitRef!!).start()
                    val text = proc.inputStream.bufferedReader().readText()
                    val exit = proc.waitFor()
                    if (exit != 0) {
                        val err = proc.errorStream.bufferedReader().readText()
                        if (err.contains("does not exist") || err.contains("fatal: path") || err.contains("unknown revision")) {
                            if (!jsonOutput) {
                                echo("ℹ️  First adoption detected: '$gitRef' not found on base branch. Initializing baseline from current attack surface.")
                            }
                            null
                        } else {
                            throw com.github.ajalt.clikt.core.UsageError("Failed to read git ref '$gitRef': $err")
                        }
                    } else {
                        SurfaceLockGenerator.deserialize(text)
                    }
                } catch (e: com.github.ajalt.clikt.core.UsageError) {
                    throw e
                } catch (e: Exception) {
                    throw com.github.ajalt.clikt.core.UsageError("Failed to parse lockfile from git ref '$gitRef': ${e.message}")
                }
            }
            else -> {
                val baseLockFile = baseTarget ?: File("surface.lock.json")
                if (!baseLockFile.exists()) {
                    throw com.github.ajalt.clikt.core.UsageError("Baseline lockfile '${baseLockFile.path}' not found. Run 'apkwarden lock' to generate one, or specify with -b/--baseline or --git-ref.")
                }
                try {
                    SurfaceLockGenerator.deserialize(baseLockFile.readText())
                } catch (e: Exception) {
                    throw com.github.ajalt.clikt.core.UsageError("Failed to parse baseline lockfile '${baseLockFile.path}': ${e.message}")
                }
            }
        }

        val headLock = if (headTarget.name.endsWith(".json")) {
            try {
                SurfaceLockGenerator.deserialize(headTarget.readText())
            } catch (e: Exception) {
                throw com.github.ajalt.clikt.core.UsageError("Failed to parse head lockfile '${headTarget.path}': ${e.message}")
            }
        } else {
            ApkAnalyzer.analyze(headTarget).surfaceLock
        }

        val effectiveBaseLock = baseLock ?: headLock
        val diffResult = if (baseLock == null) {
            SurfaceDiffResult(
                basePackageName = headLock.packageName,
                headPackageName = headLock.packageName,
                hasBreakingChanges = false,
                totalChanges = 0,
                breakingCount = 0,
                warningCount = 0,
                infoCount = 0,
                diffItems = emptyList()
            )
        } else {
            SurfaceDiffEngine.diff(baseLock, headLock)
        }

        if (jsonOutput) {
            echo(json.encodeToString(diffResult))
        } else {
            echo("")
            echo("══════════════════════════════════════════════════════════════════════")
            echo("                   APKWarden Attack Surface Diff                      ")
            echo("══════════════════════════════════════════════════════════════════════")
            echo("Base:        ${effectiveBaseLock.packageName} (targetSdk=${effectiveBaseLock.targetSdk}, SHA: ${effectiveBaseLock.sha256Fingerprint.take(8)})")
            echo("Head:        ${headLock.packageName} (targetSdk=${headLock.targetSdk}, SHA: ${headLock.sha256Fingerprint.take(8)})")
            echo("Changes:     ${diffResult.totalChanges} total (${diffResult.breakingCount} breaking, ${diffResult.warningCount} warnings, ${diffResult.infoCount} info)")
            echo("──────────────────────────────────────────────────────────────────────")

            if (diffResult.totalChanges == 0) {
                echo("✓ Attack surface matches baseline perfectly. Zero drift detected.")
            } else {
                for (item in diffResult.diffItems) {
                    val badge = when (item.severity) {
                        DiffSeverity.BREAKING -> "🚨 [BREAKING]"
                        DiffSeverity.WARNING -> "⚠️  [WARNING]"
                        DiffSeverity.INFO -> "ℹ️  [INFO]"
                    }
                    echo("$badge [${item.category}] ${item.message}")
                    if (item.detail != null) {
                        echo("    ${item.detail}")
                    }
                }
            }
            echo("══════════════════════════════════════════════════════════════════════")
        }

        // Write GitHub Action Step Summary if running in GitHub Actions
        writeGitHubDiffSummary(effectiveBaseLock, headLock, diffResult)

        if (failOnBreaking && diffResult.hasBreakingChanges) {
            if (!jsonOutput) {
                echo("❌ ATTACK SURFACE CHECK FAILED: Found ${diffResult.breakingCount} breaking attack surface change(s).")
            }
            throw ProgramResult(2)
        }
    }
}

class ScanCommand : CliktCommand(name = "scan") {
    override fun help(context: Context): String = "Perform full bytecode and attack surface security scan with 21 high-precision AppSec rules."

    private val target by argument("apk-file", help = "Path to APK, AAB, or split bundle").file(mustExist = true)
    private val jsonOutput by option("--json", help = "Output report as JSON").flag(default = false)
    private val sarifOutput by option("--sarif", help = "Export report in SARIF 2.1.0 format for GitHub Code Scanning").file()
    private val baselineFile by option("--baseline", help = "Path to .apkwarden-baseline.json to suppress grandfathered findings").file(mustExist = true)
    private val generateBaseline by option("--generate-baseline", help = "Generate a baseline JSON file containing all findings from this scan").file()
    private val failOn by option("--fail-on", help = "Exit with code 2 if active findings at or above severity exist (CRITICAL, HIGH, MEDIUM, LOW, NEVER)").default("CRITICAL")
    private val failOnLibraries by option("--fail-on-libraries", help = "Also enforce --fail-on gating against third-party library findings").flag(default = false)
    private val firstPartyPrefixes by option("--first-party", help = "Additional package prefixes to classify as first-party application code (can be specified multiple times)").multiple()

    private val json = Json { prettyPrint = true }

    override fun run() {
        if (!jsonOutput) {
            echo("Scanning ${target.name} for Android security vulnerabilities...")
        }

        val rawReport = ApkAnalyzer.scan(target, firstPartyPrefixes = firstPartyPrefixes.toSet())

        // Apply baseline if provided
        val finalFindings = if (baselineFile != null) {
            val baseline = try {
                BaselineEngine.deserialize(baselineFile!!.readText())
            } catch (e: Exception) {
                throw com.github.ajalt.clikt.core.UsageError("Failed to parse baseline file '${baselineFile!!.path}': ${e.message}")
            }
            BaselineEngine.applyBaseline(rawReport.findings, baseline)
        } else {
            rawReport.findings
        }

        val report = rawReport.copy(findings = finalFindings)

        if (generateBaseline != null) {
            val generated = BaselineEngine.generateBaseline(report.findings)
            generateBaseline!!.writeText(BaselineEngine.serialize(generated))
            if (!jsonOutput) {
                echo("✓ Generated baseline file: ${generateBaseline!!.absolutePath} (${generated.suppressions.size} suppressions)")
            }
        }

        if (sarifOutput != null) {
            val sarifJson = SarifSerializer.serialize(report)
            sarifOutput!!.writeText(sarifJson)
            if (!jsonOutput) {
                echo("✓ Exported SARIF 2.1.0 report: ${sarifOutput!!.absolutePath}")
            }
        }

        val activeFindings = report.findings.filter { !it.isSuppressed }
        val suppressedCount = report.findings.count { it.isSuppressed }

        // Partition findings for human review & gating
        // 1. Actionable Review Queue: First-party, FIRM/CERTAIN confidence, and REACHABLE or manifest declaration
        val reviewQueue = activeFindings.filter {
            it.owner == FindingOwner.FIRST_PARTY &&
                    (it.confidence == Confidence.CERTAIN || it.confidence == Confidence.FIRM) &&
                    (it.reachability == Reachability.DIRECT || it.reachability == Reachability.REACHABLE || it.targetMethod == null)
        }

        // 2. Critical Dependency & Runtime Hooks: Any CRITICAL outside first-party app code
        val criticalDependencies = activeFindings.filter {
            it.severity == Severity.CRITICAL && it.owner != FindingOwner.FIRST_PARTY
        }.distinctBy { Pair(it.id, it.targetClass) }

        // 3. App Code - Unproven Paths: First-party findings not on review queue (UNKNOWN/UNREACHABLE reachability or TENTATIVE)
        val unprovenAppFindings = activeFindings.filter {
            it.owner == FindingOwner.FIRST_PARTY && !reviewQueue.contains(it)
        }

        // 4. Third-Party Library Aggregates: Non-critical library findings
        val libraryFindings = activeFindings.filter {
            it.owner == FindingOwner.LIBRARY && it.severity != Severity.CRITICAL
        }

        // 5. Unclassified Packages: Non-critical unclassified findings
        val unclassifiedFindings = activeFindings.filter {
            it.owner == FindingOwner.UNKNOWN && it.severity != Severity.CRITICAL
        }

        if (jsonOutput) {
            echo(json.encodeToString(report))
        } else {
            val summary = report.summary
            val surface = report.attackSurface
            val fp = report.stackFingerprint

            val effectivePrefixes = (listOf(surface.packageName) + firstPartyPrefixes).distinct()
            val appScopeStr = effectivePrefixes.joinToString(", ") { "$it.*" }

            val verdictStr = when {
                reviewQueue.isEmpty() && criticalDependencies.isEmpty() ->
                    "✅ CLEAN: 0 actionable risks in application code. All dependency code within policy."
                reviewQueue.isNotEmpty() && criticalDependencies.isNotEmpty() ->
                    "🚨 ACTION REQUIRED: ${reviewQueue.size} actionable app issue(s), ${criticalDependencies.size} critical dependency hook(s)."
                reviewQueue.isNotEmpty() ->
                    "🚨 ACTION REQUIRED: ${reviewQueue.size} actionable issue(s) detected in application code."
                else ->
                    "🚨 DEPENDENCY ALERT: ${criticalDependencies.size} critical vulnerability(ies) in bundled libraries/runtime."
            }

            echo("")
            echo("══════════════════════════════════════════════════════════════════════")
            echo("                      APKWarden Security Review                       ")
            echo("══════════════════════════════════════════════════════════════════════")
            echo("Target:          ${report.apkName}")
            echo("Package:         ${surface.packageName}")
            echo("SDK Target:      minSdk=${surface.minSdk}, targetSdk=${surface.targetSdk}")
            echo("Primary Stack:   ${fp.primaryStack}")
            echo("App Scope:       $appScopeStr")
            echo("Scorecard:       App: ${summary.firstPartyScore}/100 | Libs: ${summary.libraryScore}/100 | Unclassified: ${summary.unclassifiedScore}/100")
            echo("Verdict:         $verdictStr")
            echo("──────────────────────────────────────────────────────────────────────")

            if (report.scanWarnings.isNotEmpty()) {
                echo("")
                echo("=== ⚠️  SCAN WARNINGS & BLIND SPOTS ===")
                report.scanWarnings.forEach { echo("• $it") }
            }

            // Section 1: Actionable Review Queue
            echo("")
            echo("🚨 ACTIONABLE REVIEW QUEUE (${reviewQueue.size} items)")
            echo("──────────────────────────────────────────────────────────────────────")
            if (reviewQueue.isEmpty()) {
                echo("✓ Zero high-confidence reachable vulnerabilities detected in application code.")
            } else {
                for (f in reviewQueue) {
                    val badge = when (f.severity) {
                        Severity.CRITICAL -> "🔴 [CRITICAL]"
                        Severity.HIGH -> "🟠 [HIGH]"
                        Severity.MEDIUM -> "🟡 [MEDIUM]"
                        Severity.LOW -> "🔵 [LOW]"
                        Severity.INFO -> "⚪ [INFO]"
                    }
                    val reachStr = when (f.reachability) {
                        Reachability.DIRECT -> "Direct Exported Entry"
                        Reachability.REACHABLE -> "Reachable from Exported Component"
                        Reachability.UNKNOWN -> "Manifest Declaration"
                        Reachability.UNREACHABLE -> "Internal Component"
                    }
                    val locStr = when {
                        f.targetMethod != null -> "${f.targetClass}#${f.targetMethod}${f.methodDescriptor ?: ""}"
                        f.component != null -> f.component
                        else -> surface.packageName
                    }

                    echo("• [${f.id}] ${f.title} ($badge / ${f.confidence})")
                    echo("  Location:     $locStr")
                    echo("  Reachability: $reachStr")
                    if (f.evidence != null) {
                        echo("  Evidence:     ${f.evidence}")
                    }
                    echo("  Impact:       ${f.description}")
                    echo("  Remediation:  ${f.remediation}")
                    echo("")
                }
            }

            // Section 2: Critical Dependency & Runtime Hooks
            echo("")
            echo("🚨 CRITICAL DEPENDENCY & RUNTIME HOOKS (${criticalDependencies.size} items)")
            echo("──────────────────────────────────────────────────────────────────────")
            if (criticalDependencies.isEmpty()) {
                echo("✓ Zero critical vulnerabilities detected in bundled libraries or runtime bridges.")
            } else {
                for (f in criticalDependencies) {
                    val ownerTag = if (f.owner == FindingOwner.LIBRARY) "LIBRARY" else "UNCLASSIFIED"
                    val locStr = f.targetClass?.let { "$it#${f.targetMethod ?: ""}" } ?: f.component ?: "N/A"
                    echo("• [${f.id}] ${f.title} (🔴 [CRITICAL] / [$ownerTag])")
                    echo("  Location:     $locStr")
                    if (f.evidence != null) {
                        echo("  Evidence:     ${f.evidence}")
                    }
                    echo("  Impact:       ${f.description}")
                    echo("  Remediation:  ${f.remediation}")
                    echo("")
                }
            }

            // Section 3: App Code - Unproven Paths
            echo("")
            echo("⚠️  APP CODE — UNPROVEN PATHS (${unprovenAppFindings.size} items)")
            echo("──────────────────────────────────────────────────────────────────────")
            if (unprovenAppFindings.isEmpty()) {
                echo("✓ Zero indirect or unproven sinks in first-party packages.")
            } else {
                echo("The following sinks exist in application code but static entry-point reachability is unproven:")
                for (f in unprovenAppFindings) {
                    val badge = when (f.severity) {
                        Severity.CRITICAL -> "🔴"
                        Severity.HIGH -> "🟠"
                        Severity.MEDIUM -> "🟡"
                        Severity.LOW -> "🔵"
                        Severity.INFO -> "⚪"
                    }
                    val locStr = "${f.targetClass}#${f.targetMethod ?: ""}"
                    echo("  $badge [${f.id}] ${f.title} ($locStr) [${f.confidence}]")
                }
            }

            // Section 4: Third-Party Library Aggregates (Appendix)
            echo("")
            echo("📦 THIRD-PARTY LIBRARY AGGREGATES (Appendix: ${libraryFindings.size} items)")
            echo("──────────────────────────────────────────────────────────────────────")
            if (libraryFindings.isEmpty()) {
                echo("✓ Zero library findings detected.")
            } else {
                val libGroups = libraryFindings.groupBy { Triple(it.id, it.title, it.severity) }
                for ((key, items) in libGroups) {
                    val (id, title, severity) = key
                    val badge = when (severity) {
                        Severity.CRITICAL -> "🔴"
                        Severity.HIGH -> "🟠"
                        Severity.MEDIUM -> "🟡"
                        Severity.LOW -> "🔵"
                        Severity.INFO -> "⚪"
                    }
                    val distinctPrefixes = items.mapNotNull { it.targetClass }
                        .map { it.split('.').take(2).joinToString(".") }
                        .distinct()
                        .take(3)
                        .joinToString(", ") { "$it.*" }
                    val prefixNote = if (distinctPrefixes.isNotEmpty()) " in $distinctPrefixes" else ""
                    echo("  $badge [$id] $title: ${items.size} occurrence(s)$prefixNote")
                }
                echo("  ℹ️  Detailed library findings preserved in SARIF and --json exports.")
            }

            // Section 5: Unclassified Packages
            echo("")
            echo("ℹ️  UNCLASSIFIED PACKAGES (${unclassifiedFindings.size} items)")
            echo("──────────────────────────────────────────────────────────────────────")
            if (unclassifiedFindings.isEmpty()) {
                echo("✓ Zero unclassified bytecode packages.")
            } else {
                val unclassGroups = unclassifiedFindings.groupBy {
                    it.targetClass?.split('.')?.take(2)?.joinToString(".") ?: "unknown"
                }
                for ((prefix, items) in unclassGroups) {
                    val rules = items.map { it.id }.distinct().joinToString(", ")
                    echo("  • $prefix.*: ${items.size} finding(s) across [$rules]")
                }
                echo("  Tip: Pass --first-party <prefix> if any of these packages belong to your application.")
            }

            if (suppressedCount > 0) {
                echo("")
                echo("ℹ️  Note: $suppressedCount grandfathered finding(s) suppressed via baseline.")
            }
            echo("══════════════════════════════════════════════════════════════════════")
        }

        // Write GitHub Action Step Summary if running in GitHub Actions
        writeGitHubScanSummary(target, report, reviewQueue, criticalDependencies)

        // CI Gating evaluation
        val failSeverity = when (failOn.uppercase()) {
            "CRITICAL" -> Severity.CRITICAL
            "HIGH" -> Severity.HIGH
            "MEDIUM" -> Severity.MEDIUM
            "LOW" -> Severity.LOW
            "NEVER" -> null
            else -> throw com.github.ajalt.clikt.core.UsageError("Unknown --fail-on severity '$failOn'. Valid choices: CRITICAL, HIGH, MEDIUM, LOW, NEVER")
        }

        if (failSeverity != null) {
            if (report.scanWarnings.any { it.contains("Failed to parse") }) {
                if (!jsonOutput) {
                    echo("❌ CI GATE FAILED: Fatal bytecode parsing error detected in APK. Static coverage is compromised.")
                }
                throw ProgramResult(2)
            }
            val thresholdOrdinal = failSeverity.ordinal

            // 1. Actionable Review Queue violations at/above threshold
            val reviewViolations = reviewQueue.filter { it.severity.ordinal <= thresholdOrdinal }

            // 2. Critical Dependency Hooks (CRITICAL is always blocking regardless of threshold)
            val criticalDepViolations = criticalDependencies

            // 3. Optional library gating if explicitly requested
            val libraryViolations = if (failOnLibraries) {
                libraryFindings.filter { it.severity.ordinal <= thresholdOrdinal }
            } else emptyList()

            val allViolations = reviewViolations + criticalDepViolations + libraryViolations
            if (allViolations.isNotEmpty()) {
                if (!jsonOutput) {
                    echo("")
                    echo("❌ CI GATE FAILED: Found ${allViolations.size} blocking issue(s) at or above $failSeverity threshold.")
                    if (reviewViolations.isNotEmpty()) {
                        echo("   • ${reviewViolations.size} violation(s) in Actionable Review Queue")
                    }
                    if (criticalDepViolations.isNotEmpty()) {
                        echo("   • ${criticalDepViolations.size} critical vulnerability(ies) in dependencies/runtime")
                    }
                    if (libraryViolations.isNotEmpty()) {
                        echo("   • ${libraryViolations.size} library violation(s) (--fail-on-libraries enabled)")
                    }
                }
                throw ProgramResult(2)
            } else {
                if (!jsonOutput) {
                    echo("")
                    echo("✓ CI Gate Passed: 0 blocking violations at or above $failSeverity threshold.")
                }
            }
        }
    }
}

private fun writeGitHubSummary(markdown: String) {
    val summaryPath = System.getenv("GITHUB_STEP_SUMMARY") ?: return
    try {
        File(summaryPath).appendText(markdown + "\n\n")
    } catch (_: Exception) {
        // Silently ignore if cannot write summary
    }
}

private fun writeGitHubDiffSummary(
    baseLock: SurfaceLock,
    headLock: SurfaceLock,
    diffResult: SurfaceDiffResult
) {
    val sb = StringBuilder()
    sb.appendLine("## 🔍 APKwarden Attack Surface Diff")
    sb.appendLine()
    sb.appendLine("| Metric | Baseline | Head |")
    sb.appendLine("| :--- | :--- | :--- |")
    sb.appendLine("| **Package** | `${baseLock.packageName}` | `${headLock.packageName}` |")
    sb.appendLine("| **Target SDK** | `${baseLock.targetSdk}` | `${headLock.targetSdk}` |")
    sb.appendLine("| **Total Changes** | `${diffResult.totalChanges}` | 🚨 ${diffResult.breakingCount} Breaking \\| ⚠️ ${diffResult.warningCount} Warning \\| ℹ️ ${diffResult.infoCount} Info |")
    sb.appendLine()

    if (diffResult.totalChanges == 0) {
        sb.appendLine("> ✅ **Zero Drift:** Attack surface matches baseline perfectly.")
    } else {
        sb.appendLine("### Attack Surface Changes")
        sb.appendLine()
        for (item in diffResult.diffItems) {
            val badge = when (item.severity) {
                DiffSeverity.BREAKING -> "🚨 **BREAKING**"
                DiffSeverity.WARNING -> "⚠️ **WARNING**"
                DiffSeverity.INFO -> "ℹ️ **INFO**"
            }
            sb.appendLine("- $badge `[${item.category}]` ${item.message}")
            if (item.detail != null) {
                sb.appendLine("  > ${item.detail}")
            }
        }
    }
    writeGitHubSummary(sb.toString())
}

private fun writeGitHubScanSummary(
    apkTarget: File,
    report: ScanReport,
    reviewQueue: List<Finding>,
    criticalDependencies: List<Finding>
) {
    val sb = StringBuilder()
    sb.appendLine("## 🛡️ APKwarden Security Review")
    sb.appendLine()
    sb.appendLine("| Target | Package | Target SDK | Actionable Queue | Critical Dependencies | App Health Score |")
    sb.appendLine("| :--- | :--- | :--- | :--- | :--- | :--- |")
    sb.appendLine("| `${apkTarget.name}` | `${report.attackSurface.packageName}` | `${report.attackSurface.targetSdk}` | **${reviewQueue.size} items** | **${criticalDependencies.size} items** | **${report.summary.firstPartyScore} / 100** |")
    sb.appendLine()

    if (reviewQueue.isNotEmpty()) {
        sb.appendLine("### 🚨 Actionable Review Queue")
        sb.appendLine()
        for (f in reviewQueue) {
            val badge = when (f.severity) {
                Severity.CRITICAL -> "🔴 [CRITICAL]"
                Severity.HIGH -> "🟠 [HIGH]"
                Severity.MEDIUM -> "🟡 [MEDIUM]"
                Severity.LOW -> "🔵 [LOW]"
                Severity.INFO -> "⚪ [INFO]"
            }
            sb.appendLine("<details open>")
            sb.appendLine("<summary><b>$badge [${f.id}] ${f.title}</b></summary>")
            sb.appendLine()
            sb.appendLine("- **Location:** `${f.targetClass ?: f.component ?: ""}#${f.targetMethod ?: ""}`")
            sb.appendLine("- **Reachability:** `${f.reachability}` | **Confidence:** `${f.confidence}` | **CWE:** ${f.cwe}")
            if (f.evidence != null) {
                sb.appendLine("- **Evidence:** `${f.evidence}`")
            }
            sb.appendLine()
            sb.appendLine("**Impact:** ${f.description}")
            sb.appendLine()
            sb.appendLine("**Remediation:** ${f.remediation}")
            sb.appendLine("</details>")
            sb.appendLine()
        }
    } else {
        sb.appendLine("> ✅ **Zero actionable vulnerabilities detected in application code.**")
    }

    if (criticalDependencies.isNotEmpty()) {
        sb.appendLine("### 🚨 Critical Dependency & Runtime Hooks")
        sb.appendLine()
        for (f in criticalDependencies) {
            sb.appendLine("- 🔴 **[${f.id}] ${f.title}** (`${f.targetClass}#${f.targetMethod}`) [${f.owner}]")
            if (f.evidence != null) {
                sb.appendLine("  > Evidence: `${f.evidence}`")
            }
        }
        sb.appendLine()
    }

    writeGitHubSummary(sb.toString())
}

fun main(args: Array<String>) = ApkwardenCli()
    .subcommands(
        ScanCommand(),
        DiffCommand(),
        SurfaceCommand(),
        LockCommand(),
        FingerprintCommand(),
        IngestCheckCommand()
    )
    .main(args)
