plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.prahari.spike"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.prahari.spike"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1-spike"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        // dexlib2 / guava use Java 8+ APIs; desugaring makes them safe down to minSdk 24.
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }

    buildFeatures {
        compose = true
    }
    composeOptions {
        // Must match Kotlin 1.9.24.
        kotlinCompilerExtensionVersion = "1.5.14"
    }

    packaging {
        resources {
            // apk-parser / dexlib2 / guava bundle META-INF files that collide on merge.
            // If the build ever fails with "2 files found with path 'META-INF/...'", add that
            // exact path here.
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/DEPENDENCIES"
            excludes += "META-INF/LICENSE"
            excludes += "META-INF/LICENSE.txt"
            excludes += "META-INF/NOTICE"
            excludes += "META-INF/NOTICE.txt"
            excludes += "META-INF/*.kotlin_module"
            excludes += "META-INF/versions/**"
            excludes += "**/module-info.class"
        }
    }
}

dependencies {
    // --- Jetpack Compose (matches the main build's UI stack) ---
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // --- The two libraries this spike exists to de-risk ---
    // Manifest / permissions / resources parser (pure JVM, offline).
    implementation("net.dongliu:apk-parser:2.6.10")
    // DEX bytecode reader → enumerate referenced classes/methods (pure Java, package org.jf.dexlib2).
    implementation("org.smali:dexlib2:2.5.2")
    // Force the Android-flavoured Guava (dexlib2 depends on Guava; the "jre" variant drags in
    // classes that don't exist on Android).
    implementation("com.google.guava:guava:33.2.1-android")

    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.0.4")

    debugImplementation("androidx.compose.ui:ui-tooling")
}
