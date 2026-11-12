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
    manifest {
        attributes["Main-Class"] = "io.apkwarden.cli.MainKt"
    }
}

tasks.named<JavaExec>("run") {
    workingDir = rootProject.projectDir
}
