import org.gradle.api.tasks.bundling.AbstractArchiveTask

plugins {
    id("com.android.library")
}

android {
    namespace = "dev.connetto.dioxusdemo.backup"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
    }
}

tasks.withType<AbstractArchiveTask>().configureEach {
    archiveBaseName.set("dx-native-connetto-demo-backup")
}
