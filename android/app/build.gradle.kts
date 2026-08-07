plugins {
    id("com.android.application")
    id("kotlin-android")
    id("dev.flutter.flutter-gradle-plugin")
}

val releaseSigningValues = mapOf(
    "VELOGUARD_KEYSTORE_PATH" to System.getenv("VELOGUARD_KEYSTORE_PATH"),
    "VELOGUARD_KEYSTORE_PASSWORD" to System.getenv("VELOGUARD_KEYSTORE_PASSWORD"),
    "VELOGUARD_KEY_ALIAS" to System.getenv("VELOGUARD_KEY_ALIAS"),
    "VELOGUARD_KEY_PASSWORD" to System.getenv("VELOGUARD_KEY_PASSWORD"),
)
val hasAnyReleaseSigningValue = releaseSigningValues.values.any { !it.isNullOrBlank() }
val hasCompleteReleaseSigningConfig = releaseSigningValues.values.all { !it.isNullOrBlank() }
require(!hasAnyReleaseSigningValue || hasCompleteReleaseSigningConfig) {
    "Release signing requires all VELOGUARD_KEYSTORE_* environment variables"
}

android {
    namespace = "com.blueokanna.veloguard"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = "28.2.13676358"

    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_17.toString()
    }

    defaultConfig {
        applicationId = "com.blueokanna.veloguard"
        minSdk = 24
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        
        // Do not filter Flutter's supported armeabi-v7a, arm64-v8a, and x86_64
        // libraries. Android selects the matching ABI at install time.
    }

    signingConfigs {
        if (hasCompleteReleaseSigningConfig) {
            create("release") {
                storeFile = file(releaseSigningValues.getValue("VELOGUARD_KEYSTORE_PATH")!!)
                storePassword = releaseSigningValues.getValue("VELOGUARD_KEYSTORE_PASSWORD")
                keyAlias = releaseSigningValues.getValue("VELOGUARD_KEY_ALIAS")
                keyPassword = releaseSigningValues.getValue("VELOGUARD_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            if (hasCompleteReleaseSigningConfig) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            isShrinkResources = true
        }
    }
    
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
}
