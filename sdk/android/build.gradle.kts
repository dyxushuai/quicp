plugins {
    kotlin("jvm") version "2.4.10"
}

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(17)
}

val androidJar = providers.gradleProperty("androidJar").orElse(
    providers.environmentVariable("ANDROID_HOME").map { "$it/platforms/android-21/android.jar" }
)
val example by sourceSets.creating {
    kotlin.srcDir("examples")
    compileClasspath += sourceSets.main.get().output + files(androidJar)
}

tasks.register<JavaExec>("smokeTest") {
    dependsOn(tasks.named("testClasses"))
    mainClass.set("io.quicp.QuicpEngineSmokeKt")
    classpath = sourceSets["test"].runtimeClasspath
    systemProperty("java.library.path", providers.gradleProperty("quicpJniDir").get())
}
