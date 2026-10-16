plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.prahari.auditor"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.prahari.auditor"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1-scaffold"
    }

    buildTypes {
        release { isMinifyEnabled = false }
    }
    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions { jvmTarget = "1.8" }

    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" } // pairs with Kotlin 1.9.24

    packaging {
        resources {
            // dexlib2 / apk-parser / guava bundle colliding META-INF files.
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
    // Compose
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.navigation:navigation-compose:2.7.7")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.2")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Reverse-engineering engine (proven in ../spike-re)
    implementation("net.dongliu:apk-parser:2.6.10")
    implementation("org.smali:dexlib2:2.5.2")
    implementation("com.google.guava:guava:33.2.1-android")

    // On-device ML second opinion (model trained via ../ml)
    implementation("org.tensorflow:tensorflow-lite:2.14.0")

    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.0.4")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // TODO(persistence): add Room when wiring ScanRepository to disk
    //   implementation("androidx.room:room-runtime:2.6.1")
    //   implementation("androidx.room:room-ktx:2.6.1")
    //   ksp("androidx.room:room-compiler:2.6.1")  // + id("com.google.devtools.ksp")
}
