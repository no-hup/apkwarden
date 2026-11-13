package io.apkwarden.core.rules

import io.apkwarden.core.dex.DexIndex
import io.apkwarden.core.ingest.HardenedZipReader
import io.apkwarden.core.model.*
import io.apkwarden.core.testutil.SmaliDexBuilder
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class RulesEngineTest {

    private fun createContext(
        smaliCode: String,
        targetSdk: Int = 34,
        minSdk: Int = 24,
        exportedComponents: List<String> = emptyList(),
        requestedPermissions: List<String> = emptyList(),
        netConfig: NetworkSecurityConfig? = null
    ): AnalysisContext {
        val dexBytes = SmaliDexBuilder.assemble(smaliCode)
        val baos = ByteArrayOutputStream()
        ZipOutputStream(baos).use { zos ->
            zos.putNextEntry(ZipEntry("classes.dex"))
            zos.write(dexBytes)
            zos.closeEntry()
        }

        val archive = HardenedZipReader("test.apk", baos.toByteArray())
        val dexIndex = DexIndex.build(archive)

        val components = exportedComponents.map {
            Component(
                type = ComponentType.ACTIVITY,
                name = it,
                exported = true,
                exportStatus = ExportStatus.EXPLICIT_EXPORTED
            )
        }

        val reqPerms = requestedPermissions.map { RequestedPermission(it) }

        val attackSurface = AttackSurface(
            packageName = "com.example.test",
            versionCode = 1,
            versionName = "1.0",
            minSdk = minSdk,
            targetSdk = targetSdk,
            compileSdk = 34,
            isDebuggable = false,
            isTestOnly = false,
            allowBackup = false,
            dataExtractionRulesDefined = true,
            requestedPermissions = reqPerms,
            components = components,
            networkSecurityConfig = netConfig
        )

        val fingerprint = StackFingerprint(
            primaryStack = RuntimeStack.PURE_DEX,
            detectedStacks = listOf(RuntimeStack.PURE_DEX),
            packer = PackerDetection(false, null, null, "HIGH"),
            compilerMarker = null,
            nativeLibraries = emptyList(),
            coverageStatement = CoverageStatement(
                primaryStack = RuntimeStack.PURE_DEX,
                isPacked = false,
                packerName = null,
                dexCoveragePct = 100,
                nativeCodePresent = false,
                nativeLibraryCount = 0,
                blindSpots = emptyList<String>(),
                notes = emptyList<String>()
            )
        )

        return AnalysisContext(archive, attackSurface, fingerprint, dexIndex)
    }

    @Test
    fun `flags insecure crypto ECB mode and passes secure GCM mode`() {
        val vulnerableSmali = """
            .class public Lcom/example/VulnerableCrypto;
            .super Ljava/lang/Object;
            
            .method public encrypt()V
                .registers 2
                const-string v0, "AES/ECB/PKCS5Padding"
                invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
                return-void
            .end method
        """.trimIndent()

        val ctxVuln = createContext(vulnerableSmali)
        val findingsVuln = InsecureCryptoRule().analyze(ctxVuln)
        assertThat(findingsVuln).hasSize(1)
        assertThat(findingsVuln[0].id).isEqualTo("APK-SEC-011")
        assertThat(findingsVuln[0].severity).isEqualTo(Severity.HIGH)

        val secureSmali = """
            .class public Lcom/example/SecureCrypto;
            .super Ljava/lang/Object;
            
            .method public encrypt()V
                .registers 2
                const-string v0, "AES/GCM/NoPadding"
                invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
                return-void
            .end method
        """.trimIndent()

        val ctxSec = createContext(secureSmali)
        val findingsSec = InsecureCryptoRule().analyze(ctxSec)
        assertThat(findingsSec).isEmpty()
    }

    @Test
    fun `flags mutable pending intent on targetSdk 31+`() {
        val smali = """
            .class public Lcom/example/PendingIntentTest;
            .super Ljava/lang/Object;
            
            .method public createIntent(Landroid/content/Context;Landroid/content/Intent;)V
                .registers 6
                const/4 v1, 0x0
                const/high16 v3, 0x2000000
                invoke-static {p0, v1, p1, v3}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, targetSdk = 31)
        val findings = MutablePendingIntentRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-002")
        assertThat(findings[0].severity).isEqualTo(Severity.HIGH)
    }

    @Test
    fun `flags dynamic receiver registration missing export flag on targetSdk 34`() {
        val smali = """
            .class public Lcom/example/ReceiverTest;
            .super Ljava/lang/Object;
            
            .method public reg(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)V
                .registers 4
                invoke-virtual {p1, p2, p3}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, targetSdk = 34)
        val findings = DynamicReceiverExportRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-004")
    }

    @Test
    fun `flags insecure custom X509TrustManager bypassing SSL`() {
        val smali = """
            .class public Lcom/example/InsecureTrustManager;
            .super Ljava/lang/Object;
            .implements Ljavax/net/ssl/X509TrustManager;
            
            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                return-void
            .end method
            
            .method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                return-void
            .end method
            
            .method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
                .registers 2
                const/4 v0, 0x0
                return-object v0
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = InsecureTrustManagerRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-013")
        assertThat(findings[0].severity).isEqualTo(Severity.CRITICAL)
    }

    @Test
    fun `flags custom HostnameVerifier returning true unconditionally`() {
        val smali = """
            .class public Lcom/example/BadVerifier;
            .super Ljava/lang/Object;
            .implements Ljavax/net/ssl/HostnameVerifier;
            
            .method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
                .registers 4
                const/4 v0, 0x1
                return v0
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = AllowAllHostnameVerifierRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-014")
        assertThat(findings[0].severity).isEqualTo(Severity.CRITICAL)
    }

    @Test
    fun `flags zip slip vulnerability when canonical check is absent`() {
        val smali = """
            .class public Lcom/example/ZipExtractor;
            .super Ljava/lang/Object;
            
            .method public unzip(Ljava/util/zip/ZipInputStream;)V
                .registers 6
                invoke-virtual {p1}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;
                move-result-object v0
                invoke-virtual {v0}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;
                move-result-object v1
                new-instance v2, Ljava/io/File;
                const-string v3, "/sdcard/extracted"
                invoke-direct {v2, v3, v1}, Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = ZipSlipRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-006")
    }

    @Test
    fun `flags dirty stream traversal when openInputStream uses unvalidated uri path segment in exported class`() {
        val smali = """
            .class public Lcom/example/ExportedHandler;
            .super Ljava/lang/Object;
            
            .method public handleStream(Landroid/content/ContentResolver;Landroid/net/Uri;)V
                .registers 4
                invoke-virtual {p1, p2}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;
                move-result-object v0
                invoke-virtual {p2}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;
                move-result-object v1
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, exportedComponents = listOf("com.example.ExportedHandler"))
        val findings = DirtyStreamTraversalRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-005")
        assertThat(findings[0].severity).isEqualTo(Severity.CRITICAL)
    }

    @Test
    fun `flags hardcoded AWS and Google API secrets`() {
        val smali = """
            .class public Lcom/example/SecretsDemo;
            .super Ljava/lang/Object;
            
            .method public getKeys()V
                .registers 3
                const-string v0, "AKIAIOSFODNN7EXAMPLE"
                const-string v1, "AIzaSyD-1234567890abcdefghijklmnopqrstu"
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = HardcodedSecretsRule().analyze(ctx)
        assertThat(findings).hasSize(2)
        assertThat(findings.map { it.title }).contains(
            "Hardcoded AWS Access Key ID Detected",
            "Hardcoded Google API Key Detected"
        )
    }

    @Test
    fun `flags SQL injection via dynamic concatenation in rawQuery`() {
        val smali = """
            .class public Lcom/example/SqlDemo;
            .super Ljava/lang/Object;
            
            .method public query(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)V
                .registers 6
                new-instance v0, Ljava/lang/StringBuilder;
                invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
                const-string v1, "SELECT * FROM users WHERE name = "
                invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
                invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
                invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
                move-result-object v2
                const/4 v3, 0x0
                invoke-virtual {p1, v2, v3}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = SqlInjectionRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-015")
    }

    @Test
    fun `flags world readable file mode`() {
        val smali = """
            .class public Lcom/example/FileModeDemo;
            .super Ljava/lang/Object;
            
            .method public write(Landroid/content/Context;)V
                .registers 4
                const-string v0, "sensitive.dat"
                const/4 v1, 0x1
                invoke-virtual {p0, v0, v1}, Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = WorldReadableWritableRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-016")
    }

    @Test
    fun `flags sensitive token stored in plaintext SharedPreferences`() {
        val smali = """
            .class public Lcom/example/PrefsDemo;
            .super Ljava/lang/Object;
            
            .method public saveToken(Landroid/content/SharedPreferences${'$'}Editor;Ljava/lang/String;)V
                .registers 4
                const-string v0, "auth_token"
                invoke-interface {p1, v0, p2}, Landroid/content/SharedPreferences${'$'}Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences${'$'}Editor;
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = InsecureSharedPrefsRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-020")
    }

    @Test
    fun `flags arbitrary URL loaded into WebView in exported component`() {
        val smali = """
            .class public Lcom/example/ExportedWebActivity;
            .super Landroid/app/Activity;
            
            .method public handleIntent(Landroid/webkit/WebView;)V
                .registers 5
                invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
                move-result-object v0
                const-string v1, "target_url"
                invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
                move-result-object v2
                invoke-virtual {p1, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, exportedComponents = listOf("com.example.ExportedWebActivity"))
        val findings = WebViewArbitraryUrlRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-007")
        assertThat(findings[0].severity).isEqualTo(Severity.HIGH)
    }

    @Test
    fun `does not flag arbitrary WebView loadUrl when component is internal and unexported`() {
        val smali = """
            .class public Lcom/example/InternalWebActivity;
            .super Landroid/app/Activity;
            
            .method public handleIntent(Landroid/webkit/WebView;)V
                .registers 5
                invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
                move-result-object v0
                const-string v1, "target_url"
                invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
                move-result-object v2
                invoke-virtual {p1, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
                return-void
            .end method
        """.trimIndent()

        // Not exported!
        val ctx = createContext(smali, exportedComponents = emptyList())
        val findings = WebViewArbitraryUrlRule().analyze(ctx)
        assertThat(findings).isEmpty() // Suppressed due to zero reachability!
    }

    @Test
    fun `flags webview ssl bypass when onReceivedSslError calls proceed`() {
        val smali = """
            .class public Lcom/example/InsecureWebClient;
            .super Landroid/webkit/WebViewClient;
            
            .method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
                .registers 4
                invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = WebViewSslBypassRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-021")
        assertThat(findings[0].severity).isEqualTo(Severity.CRITICAL)
    }

    @Test
    fun `does not flag RSA ECB OAEP padding cipher`() {
        val smali = """
            .class public Lcom/example/RsaCipherDemo;
            .super Ljava/lang/Object;
            
            .method public encrypt()V
                .registers 2
                const-string v0, "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
                invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = InsecureCryptoRule().analyze(ctx)
        assertThat(findings).isEmpty() // Excluded from false positive!
    }

    @Test
    fun `does not flag explicit Intent constructor in PendingIntent`() {
        val smali = """
            .class public Lcom/example/ExplicitPendingIntent;
            .super Ljava/lang/Object;
            
            .method public makeIntent(Landroid/content/Context;)V
                .registers 6
                new-instance v0, Landroid/content/Intent;
                const-class v1, Lcom/example/ExplicitPendingIntent;
                invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
                const/4 v2, 0x0
                const/high16 v3, 0x4000000
                invoke-static {p1, v2, v0, v3}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = ImplicitPendingIntentRule().analyze(ctx)
        assertThat(findings).isEmpty()
    }

    @Test
    fun `does not flag registerReceiver with null receiver battery check`() {
        val smali = """
            .class public Lcom/example/BatteryCheck;
            .super Ljava/lang/Object;
            
            .method public check(Landroid/content/Context;Landroid/content/IntentFilter;)V
                .registers 4
                const/4 v0, 0x0
                invoke-virtual {p1, v0, p2}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, targetSdk = 34)
        val findings = DynamicReceiverExportRule().analyze(ctx)
        assertThat(findings).isEmpty()
    }

    @Test
    fun `seeds intent parameter in exported onReceive and detects redirection`() {
        val smali = """
            .class public Lcom/example/ExportedReceiver;
            .super Landroid/content/BroadcastReceiver;
            
            .method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
                .registers 3
                invoke-virtual {p1, p2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, exportedComponents = listOf("com.example.ExportedReceiver"))
        val findings = IntentRedirectionRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-001")
        assertThat(findings[0].severity).isEqualTo(Severity.CRITICAL)
    }

    @Test
    fun `does not flag intent redirection when intent is sanitized with setPackage`() {
        val smali = """
            .class public Lcom/example/SanitizedReceiver;
            .super Landroid/content/BroadcastReceiver;
            
            .method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
                .registers 4
                invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
                move-result-object v0
                invoke-virtual {p2, v0}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;
                invoke-virtual {p1, p2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, exportedComponents = listOf("com.example.SanitizedReceiver"))
        val findings = IntentRedirectionRule().analyze(ctx)
        assertThat(findings).isEmpty()
    }

    @Test
    fun `downgrades intent redirection to MEDIUM with UNKNOWN reachability when caller is non-component helper`() {
        val smali = """
            .class public Lcom/example/DeepHelper;
            .super Ljava/lang/Object;
            
            .method public static forward(Landroid/content/Context;Landroid/content/Intent;)V
                .registers 4
                const-string v0, "nested_intent"
                invoke-virtual {p1, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;
                move-result-object v1
                check-cast v1, Landroid/content/Intent;
                invoke-virtual {p0, v1}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, exportedComponents = listOf("com.example.MainActivity"))
        val findings = IntentRedirectionRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        val f = findings.first()
        assertThat(f.reachability).isEqualTo(io.apkwarden.core.model.Reachability.UNKNOWN)
        assertThat(f.severity).isEqualTo(io.apkwarden.core.model.Severity.MEDIUM)
        assertThat(f.confidence).isEqualTo(io.apkwarden.core.model.Confidence.TENTATIVE)
    }

    @Test
    fun `does not flag custom X509TrustManager when checkServerTrusted delegates to sibling method that throws`() {
        val smali = """
            .class public Lcom/example/DelegatingTrustManager;
            .super Ljava/lang/Object;
            .implements Ljavax/net/ssl/X509TrustManager;

            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                invoke-direct {p0, p1, p2}, Lcom/example/DelegatingTrustManager;->verifyHelper([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                return-void
            .end method

            .method private verifyHelper([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 4
                new-instance v0, Ljava/security/cert/CertificateException;
                invoke-direct {v0}, Ljava/security/cert/CertificateException;-><init>()V
                throw v0
            .end method

            .method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                return-void
            .end method

            .method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
                .registers 2
                const/4 v0, 0x0
                return-object v0
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = InsecureTrustManagerRule().analyze(ctx)
        assertThat(findings).isEmpty()
    }

    @Test
    fun `flags custom X509TrustManager when checkServerTrusted delegates to sibling that only logs and returns void`() {
        val smali = """
            .class public Lcom/example/LoggingTrustManager;
            .super Ljava/lang/Object;
            .implements Ljavax/net/ssl/X509TrustManager;

            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                invoke-direct {p0, p1, p2}, Lcom/example/LoggingTrustManager;->logHelper([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                return-void
            .end method

            .method private logHelper([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                return-void
            .end method

            .method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                return-void
            .end method

            .method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
                .registers 2
                const/4 v0, 0x0
                return-object v0
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = InsecureTrustManagerRule().analyze(ctx)
        assertThat(findings).hasSize(1)
        assertThat(findings[0].id).isEqualTo("APK-SEC-013")
        assertThat(findings[0].severity).isEqualTo(Severity.CRITICAL)
    }

    @Test
    fun `cleartext rule matches host precisely, skipping XML schemas but catching evil query spoofing`() {
        val smali = """
            .class public Lcom/example/CleartextDemo;
            .super Ljava/lang/Object;

            .method public testUrls()V
                .registers 5
                const-string v0, "http://www.w3.org/2000/svg"
                const-string v1, "http://javax.xml.XMLConstants/feature/secure-processing"
                const-string v2, "http://evil.com/leak?target=w3.org"
                const-string v3, "http://10.0.2.2/api/v1/auth"
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali, targetSdk = 26)
        val findings = CleartextTrafficRule().analyze(ctx)
        val endpointFindings = findings.filter { it.title == "Cleartext HTTP Host in Application Bytecode" }
        assertThat(endpointFindings).anyMatch { it.description.contains("'evil.com'") }
        assertThat(endpointFindings).anyMatch { it.description.contains("'10.0.2.2'") }
        assertThat(endpointFindings).noneMatch { it.description.contains("'w3.org'") || it.description.contains("'www.w3.org'") }
    }

    @Test
    fun `sql injection skips constant string builder query but flags dynamic concatenation`() {
        val smali = """
            .class public Lcom/example/SqlBuilderDemo;
            .super Ljava/lang/Object;

            .method public safeCreate(Landroid/database/sqlite/SQLiteDatabase;)V
                .registers 5
                new-instance v0, Ljava/lang/StringBuilder;
                invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
                const-string v1, "CREATE TABLE users ("
                invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
                const-string v2, "id INTEGER PRIMARY KEY, name TEXT)"
                invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
                invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
                move-result-object v3
                invoke-virtual {p1, v3}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = SqlInjectionRule().analyze(ctx)
        assertThat(findings).isEmpty()
    }

    @Test
    fun `hardcoded secrets classifies telemetry tokens and suppresses dotted identifiers`() {
        val smali = """
            .class public Lcom/example/SecretsRefinementDemo;
            .super Ljava/lang/Object;

            .method public testStrings()V
                .registers 5
                const-string v0, "phc_1234567890abcdef1234567890abcdef"
                const-string v1, "https://0123456789abcdef0123456789abcdef@o123456.ingest.sentry.io/7890"
                const-string v2, "pub0123456789abcdef0123456789abcdef"
                const-string v3, "com.wispr.flowapp.service.ACTION_PERMISSION_GRANTED"
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = HardcodedSecretsRule().analyze(ctx)

        val posthog = findings.find { it.title.contains("PostHog") }
        assertThat(posthog).isNotNull
        assertThat(posthog!!.severity).isEqualTo(Severity.INFO)
        assertThat(posthog.confidence).isEqualTo(Confidence.CERTAIN)

        val sentry = findings.find { it.title.contains("Sentry") }
        assertThat(sentry).isNotNull
        assertThat(sentry!!.severity).isEqualTo(Severity.INFO)
        assertThat(sentry.confidence).isEqualTo(Confidence.CERTAIN)

        val datadog = findings.find { it.title.contains("Datadog") }
        assertThat(datadog).isNotNull
        assertThat(datadog!!.severity).isEqualTo(Severity.LOW)
        assertThat(datadog.confidence).isEqualTo(Confidence.TENTATIVE)

        assertThat(findings.any { it.evidence?.contains("ACTION_PERMISSION_GRANTED") == true }).isFalse()
    }

    @Test
    fun `flags real PEM private key but ignores bare parser header string`() {
        val smali = """
            .class public Lcom/example/PemDemo;
            .super Ljava/lang/Object;

            .method public testKeys()V
                .registers 3
                const-string v0, "-----BEGIN PRIVATE KEY-----"
                const-string v1, "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0Y1+abcdefghijklmn1234567890\\n-----END RSA PRIVATE KEY-----"
                return-void
            .end method
        """.trimIndent()

        val ctx = createContext(smali)
        val findings = HardcodedSecretsRule().analyze(ctx)
        val pemFindings = findings.filter { it.title.contains("PEM Encoded Private Key") }
        assertThat(pemFindings).hasSize(1)
        assertThat(pemFindings[0].severity).isEqualTo(Severity.CRITICAL)
    }
}
