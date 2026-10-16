buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        classpath("com.android.tools.build:gradle:9.3.1")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.2.10")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

// The tauri-android library is built from its sources in cargo's registry,
// which the emi runner VMs share, so its output goes under this project.
subprojects {
    if (name == "tauri-android") {
        layout.buildDirectory.set(rootProject.layout.buildDirectory.dir("tauri-android"))
    }
}

tasks.register("clean").configure {
    delete("build")
}

