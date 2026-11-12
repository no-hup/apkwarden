package io.apkwarden.core.dex

import io.apkwarden.core.testutil.SmaliDexBuilder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class DisassemblySnippetTest {

    @Test
    fun `extracts disassembly snippet centered around target instruction with arrow marker`() {
        val smali = """
            .class public Lcom/example/SnippetTest;
            .super Ljava/lang/Object;
            
            .method public testSnippet()V
                .registers 3
                const-string v0, "hello"
                const-string v1, "world"
                invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
                move-result-object v2
                return-void
            .end method
        """.trimIndent()

        val dexBytes = SmaliDexBuilder.assemble(smali)
        val dexFile = com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile(
            com.android.tools.smali.dexlib2.Opcodes.forApi(34),
            dexBytes
        )
        val classDef = dexFile.classes.first()
        val method = classDef.methods.first()
        val analyzer = MethodAnalyzer(method)

        // Instruction index 2 is the invoke-virtual call
        val snippet = analyzer.getDisassemblySnippet(2, window = 1)
        assertThat(snippet).contains("> 0002: invoke-virtual Ljava/lang/String;->concat")
        assertThat(snippet).contains("  0001: const-string \"world\"")
        assertThat(snippet).contains("  0003: move-result-object")
    }
}
