import org.gradle.api.tasks.bundling.AbstractArchiveTask

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.connetto.peer"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        // btleplug's Java is reached from native code only, so a shrinking
        // application build keeps it through these rules.
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

tasks.withType<AbstractArchiveTask>().configureEach {
    archiveBaseName.set("dx-native-connetto-peer")
}

dependencies {
    // The Activity result registry the Bluetooth prompt answers through,
    // which the application's AppCompat already brings.
    compileOnly("androidx.activity:activity:1.8.0")
}

// Every configuration resolves to the versions `gradle.lockfile` beside this
// file pins, written with `./gradlew :plugins:<module>:dependencies
// --write-locks` inside the app's generated Android build.
dependencyLocking {
    lockAllConfigurations()
}
