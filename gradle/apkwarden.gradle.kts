//
// APKwarden Gradle Integration Script
// Drop-in security scanner and attack surface gate for Android projects.
//
// Usage in app/build.gradle.kts:
//   apply(from = "https://raw.githubusercontent.com/no-hup/apkwarden/main/gradle/apkwarden.gradle.kts")
// Or locally:
//   apply(from = "$rootDir/gradle/apkwarden.gradle.kts")
//

val apkwardenVersion = "0.1.0"
val apkwardenJarUrl = "https://github.com/no-hup/apkwarden/releases/download/v$apkwardenVersion/apkwarden-v$apkwardenVersion-all.jar"
val apkwardenCacheDir = File(rootProject.buildDir, "apkwarden")
val apkwardenJarFile = File(apkwardenCacheDir, "apkwarden-$apkwardenVersion-all.jar")

val downloadApkwardenTask = tasks.register("downloadApkwarden") {
    group = "security"
    description = "Downloads APKwarden standalone executable JAR"
    outputs.file(apkwardenJarFile)

    doLast {
        if (!apkwardenJarFile.exists()) {
            apkwardenCacheDir.mkdirs()
            println("⬇️ Downloading APKwarden v$apkwardenVersion...")
            java.net.URI(apkwardenJarUrl).toURL().openStream().use { input ->
                apkwardenJarFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            println("✓ Downloaded APKwarden to ${apkwardenJarFile.absolutePath}")
        }
    }
}

fun findTargetArtifact(): File? {
    val buildOutputsDir = File(project.buildDir, "outputs")
    val releaseApk = File(buildOutputsDir, "apk/release").walkTopDown().firstOrNull { it.extension == "apk" && !it.name.contains("unaligned") }
    if (releaseApk != null) return releaseApk

    val releaseAab = File(buildOutputsDir, "bundle/release").walkTopDown().firstOrNull { it.extension == "aab" }
    if (releaseAab != null) return releaseAab

    // Fallback to any built APK
    return File(buildOutputsDir, "apk").walkTopDown().firstOrNull { it.extension == "apk" && !it.name.contains("unaligned") }
}

tasks.register<JavaExec>("apkwardenScan") {
    group = "security"
    description = "Runs APKwarden static security scan on the built APK or AAB"
    dependsOn(downloadApkwardenTask)

    doFirst {
        val artifact = findTargetArtifact() ?: throw GradleException("No APK or AAB found in build/outputs. Run 'assembleRelease' or 'bundleRelease' first.")
        val reportsDir = File(project.buildDir, "reports/apkwarden").apply { mkdirs() }
        val sarifReport = File(reportsDir, "apkwarden-results.sarif")

        classpath = files(apkwardenJarFile)
        mainClass.set("io.apkwarden.cli.MainKt")
        args = listOf("scan", artifact.absolutePath, "--sarif", sarifReport.absolutePath, "--fail-on", "HIGH")
    }
}

tasks.register<JavaExec>("apkwardenLock") {
    group = "security"
    description = "Generates surface.lock.json for the built APK or AAB"
    dependsOn(downloadApkwardenTask)

    doFirst {
        val artifact = findTargetArtifact() ?: throw GradleException("No APK or AAB found in build/outputs. Run 'assembleRelease' first.")
        val lockFile = File(rootProject.projectDir, "surface.lock.json")

        classpath = files(apkwardenJarFile)
        mainClass.set("io.apkwarden.cli.MainKt")
        args = listOf("lock", artifact.absolutePath, "-o", lockFile.absolutePath)
    }
}

tasks.register<JavaExec>("apkwardenDiff") {
    group = "security"
    description = "Compares attack surface of built APK against surface.lock.json"
    dependsOn(downloadApkwardenTask)

    doFirst {
        val artifact = findTargetArtifact() ?: throw GradleException("No APK or AAB found in build/outputs. Run 'assembleRelease' first.")
        val lockFile = File(rootProject.projectDir, "surface.lock.json")
        if (!lockFile.exists()) {
            throw GradleException("Baseline lockfile '${lockFile.path}' not found. Run './gradlew apkwardenLock' first to generate one.")
        }

        classpath = files(apkwardenJarFile)
        mainClass.set("io.apkwarden.cli.MainKt")
        args = listOf("diff", artifact.absolutePath, "-b", lockFile.absolutePath, "--fail-on-breaking")
    }
}
