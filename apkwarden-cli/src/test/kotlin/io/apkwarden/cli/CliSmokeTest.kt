package io.apkwarden.cli

import com.github.ajalt.clikt.core.PrintHelpMessage
import com.github.ajalt.clikt.core.PrintMessage
import com.github.ajalt.clikt.core.UsageError
import com.github.ajalt.clikt.core.parse
import com.github.ajalt.clikt.core.subcommands
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class CliSmokeTest {

    private fun createCli(): ApkwardenCli = ApkwardenCli().subcommands(
        ScanCommand(),
        DiffCommand(),
        SurfaceCommand(),
        LockCommand(),
        FingerprintCommand(),
        IngestCheckCommand()
    )

    @Test
    fun testVersionFlag() {
        val cli = createCli()
        assertThatThrownBy { cli.parse(listOf("--version")) }
            .isInstanceOf(PrintMessage::class.java)
            .hasMessageContaining("0.1.0")
    }

    @Test
    fun testHelpFlag() {
        val cli = createCli()
        assertThatThrownBy { cli.parse(listOf("--help")) }
            .isInstanceOf(PrintHelpMessage::class.java)
    }

    @Test
    fun testSubcommandHelp() {
        val cli = createCli()
        assertThatThrownBy { cli.parse(listOf("scan", "--help")) }
            .isInstanceOf(PrintHelpMessage::class.java)
    }

    private fun findSampleApk(): File {
        val candidates = listOf(
            File("samples/sample-safe.apk"),
            File("../samples/sample-safe.apk"),
            File("../../samples/sample-safe.apk")
        )
        return candidates.firstOrNull { it.exists() }
            ?: throw IllegalStateException("sample-safe.apk not found in candidates: $candidates")
    }

    @Test
    fun testInvalidFailOnOption() {
        val sampleApk = findSampleApk()
        val cli = createCli()
        assertThatThrownBy { cli.parse(listOf("scan", sampleApk.absolutePath, "--fail-on", "INVALID_SEVERITY")) }
            .isInstanceOf(UsageError::class.java)
            .hasMessageContaining("Unknown --fail-on severity 'INVALID_SEVERITY'")
    }

    @Test
    fun testMissingTargetFile() {
        val cli = createCli()
        assertThatThrownBy { cli.parse(listOf("scan", "/non/existent/path/app.apk")) }
            .isInstanceOf(UsageError::class.java)
    }
}
