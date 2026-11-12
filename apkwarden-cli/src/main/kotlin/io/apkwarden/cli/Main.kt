package io.apkwarden.cli

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.Context
import com.github.ajalt.clikt.core.ProgramResult
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.default
import com.github.ajalt.clikt.parameters.options.flag
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.options.versionOption
import com.github.ajalt.clikt.parameters.types.file
import io.apkwarden.core.ApkAnalyzer
import io.apkwarden.core.baseline.BaselineEngine
import io.apkwarden.core.diff.DiffSeverity
import io.apkwarden.core.diff.SurfaceDiffEngine
import io.apkwarden.core.diff.SurfaceDiffResult
import io.apkwarden.core.lock.SurfaceLockGenerator
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

    private val json = Json { prettyPrint = true }

    override fun run() {
        if (!jsonOutput) {
            echo("Scanning ${target.name} for Android security vulnerabilities...")
        }

        val rawReport = ApkAnalyzer.scan(target)

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

        if (jsonOutput) {
            echo(json.encodeToString(report))
        } else {
            val summary = report.summary
            val surface = report.attackSurface
            val fp = report.stackFingerprint
            val activeFindings = report.findings.filter { !it.isSuppressed }
            val suppressedCount = report.findings.count { it.isSuppressed }

            echo("")
            echo("══════════════════════════════════════════════════════════════════════")
            echo("                      APKWarden Security Report                       ")
            echo("══════════════════════════════════════════════════════════════════════")
            echo("Target:          ${report.apkName}")
            echo("Package:         ${surface.packageName}")
            echo("SDK Target:      minSdk=${surface.minSdk}, targetSdk=${surface.targetSdk}")
            echo("Primary Stack:   ${fp.primaryStack}")
            echo("Security Score:  ${summary.securityScore}/100")
            val suppStr = if (suppressedCount > 0) " | SUPPRESSED: $suppressedCount" else ""
            echo("Findings:        CRITICAL: ${summary.criticalCount} | HIGH: ${summary.highCount} | MEDIUM: ${summary.mediumCount} | LOW: ${summary.lowCount} | INFO: ${summary.infoCount}$suppStr")
            echo("──────────────────────────────────────────────────────────────────────")

            if (report.scanWarnings.isNotEmpty()) {
                echo("")
                echo("=== ⚠️  SCAN WARNINGS & BLIND SPOTS ===")
                report.scanWarnings.forEach { echo("• $it") }
            }

            if (activeFindings.isEmpty()) {
                echo("")
                if (suppressedCount > 0) {
                    echo("✓ Zero active vulnerabilities ($suppressedCount grandfathered findings suppressed by baseline).")
                } else if (report.scanWarnings.any { it.contains("PACKER") || it.contains("Failed to parse") }) {
                    echo("⚠️  No static findings detected in available DEX bytecode, but note scan warnings/blind spots above.")
                } else {
                    echo("✓ No active findings detected across 21 AppSec rules.")
                }
            } else {
                var currentSeverity: Severity? = null
                for (finding in report.findings) {
                    if (finding.isSuppressed) continue

                    if (finding.severity != currentSeverity) {
                        currentSeverity = finding.severity
                        val badge = when (currentSeverity) {
                            Severity.CRITICAL -> "🔴 [CRITICAL]"
                            Severity.HIGH -> "🟠 [HIGH]"
                            Severity.MEDIUM -> "🟡 [MEDIUM]"
                            Severity.LOW -> "🔵 [LOW]"
                            Severity.INFO -> "⚪ [INFO]"
                        }
                        echo("")
                        echo("=== $badge FINDINGS ===")
                    }

                    val reachabilityBadge = when (finding.reachability) {
                        Reachability.DIRECT -> "[DIRECT]"
                        Reachability.REACHABLE -> "[REACHABLE]"
                        Reachability.UNKNOWN -> "[UNKNOWN/INDIRECT]"
                        Reachability.UNREACHABLE -> "[UNREACHABLE]"
                    }

                    echo("• [${finding.id}] ${finding.title} ($reachabilityBadge ${finding.cwe} / ${finding.owasp})")
                    echo("  Confidence:   ${finding.confidence}")
                    if (finding.component != null) {
                        echo("  Component:    ${finding.component}")
                    }
                    if (finding.targetMethod != null) {
                        echo("  Method:       ${finding.targetClass}#${finding.targetMethod}")
                    }
                    if (finding.evidence != null) {
                        echo("  Evidence:     ${finding.evidence}")
                    }
                    val snippet = finding.codeSnippet
                    if (snippet != null) {
                        echo("  Bytecode Snippet:")
                        snippet.lines().forEach { line ->
                            echo("    $line")
                        }
                    }
                    echo("  Description:  ${finding.description}")
                    echo("  Remediation:  ${finding.remediation}")
                    echo("")
                }

                if (suppressedCount > 0) {
                    echo("ℹ️  Note: $suppressedCount grandfathered finding(s) suppressed via baseline.")
                }
            }
            echo("══════════════════════════════════════════════════════════════════════")
        }

        // Write GitHub Action Step Summary if running in GitHub Actions
        writeGitHubScanSummary(target, report)

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
            val violations = report.findings.filter { !it.isSuppressed && it.severity.ordinal <= thresholdOrdinal }
            if (violations.isNotEmpty()) {
                if (!jsonOutput) {
                    echo("❌ CI GATE FAILED: Found ${violations.size} active finding(s) at or above $failSeverity threshold.")
                }
                throw ProgramResult(2)
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
    report: ScanReport
) {
    val activeFindings = report.findings.filter { !it.isSuppressed }
    val crit = activeFindings.count { it.severity == Severity.CRITICAL }
    val high = activeFindings.count { it.severity == Severity.HIGH }
    val med = activeFindings.count { it.severity == Severity.MEDIUM }
    val low = activeFindings.count { it.severity == Severity.LOW }

    val sb = StringBuilder()
    sb.appendLine("## 🛡️ APKwarden Security Report")
    sb.appendLine()
    sb.appendLine("| Target | Package | Target SDK | Security Score | Active Findings |")
    sb.appendLine("| :--- | :--- | :--- | :--- | :--- |")
    sb.appendLine("| `${apkTarget.name}` | `${report.attackSurface.packageName}` | `${report.attackSurface.targetSdk}` | **${report.summary.securityScore} / 100** | 🔴 $crit Critical \\| 🟠 $high High \\| 🟡 $med Med \\| 🔵 $low Low |")
    sb.appendLine()

    val topFindings = activeFindings.filter { it.severity == Severity.CRITICAL || it.severity == Severity.HIGH }
    if (topFindings.isNotEmpty()) {
        sb.appendLine("### 🚨 High & Critical Vulnerabilities")
        sb.appendLine()
        for (f in topFindings) {
            val badge = if (f.severity == Severity.CRITICAL) "🔴 [CRITICAL]" else "🟠 [HIGH]"
            sb.appendLine("<details open>")
            sb.appendLine("<summary><b>$badge [${f.id}] ${f.title}</b></summary>")
            sb.appendLine()
            sb.appendLine("- **Component:** `${f.component ?: "N/A"}`")
            sb.appendLine("- **Method:** `${f.targetClass ?: ""}#${f.targetMethod ?: ""}`")
            sb.appendLine("- **Reachability:** `${f.reachability}` | **CWE:** ${f.cwe} | **OWASP:** ${f.owasp}")
            if (f.evidence != null) {
                sb.appendLine("- **Evidence:** `${f.evidence}`")
            }
            if (f.codeSnippet != null) {
                sb.appendLine()
                sb.appendLine("```smali")
                sb.appendLine(f.codeSnippet)
                sb.appendLine("```")
            }
            sb.appendLine()
            sb.appendLine("**Description:** ${f.description}")
            sb.appendLine()
            sb.appendLine("**Remediation:** ${f.remediation}")
            sb.appendLine("</details>")
            sb.appendLine()
        }
    } else if (activeFindings.isEmpty()) {
        sb.appendLine("> ✅ **No active findings detected across 21 AppSec rules.**")
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
