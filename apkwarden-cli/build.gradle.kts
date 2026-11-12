plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    application
}

application {
    applicationName = "apkwarden"
    mainClass.set("io.apkwarden.cli.MainKt")
}

dependencies {
    implementation(project(":apkwarden-core"))
    implementation("com.github.ajalt.clikt:clikt:5.0.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
    testImplementation("org.assertj:assertj-core:3.26.3")
}

tasks.named<Jar>("jar") {
    archiveBaseName.set("apkwarden")
    manifest {
        attributes["Main-Class"] = "io.apkwarden.cli.MainKt"
    }
}

tasks.register<Jar>("fatJar") {
    archiveBaseName.set("apkwarden")
    archiveClassifier.set("all")
    manifest {
        attributes["Main-Class"] = "io.apkwarden.cli.MainKt"
    }
    from(sourceSets.main.get().output)
    from(configurations.runtimeClasspath.map { config ->
        config.filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

tasks.named("assemble") {
    dependsOn("fatJar")
}

tasks.named<JavaExec>("run") {
    workingDir = rootProject.projectDir
}
