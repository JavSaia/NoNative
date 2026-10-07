plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.nonative"
    compileSdk = 36
    buildToolsVersion = "35.0.0"

    defaultConfig {
        applicationId = "com.example.nonative"
        minSdk = 29
        targetSdk = 36
        versionCode = 2
        versionName = "1.0.0"
    }

    signingConfigs {
        // reuse the debug keystore so the release APK is installable without
        // shipping secrets; swap in a dedicated keystore before wide distribution
        getByName("debug")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    lint {
        abortOnError = false
        disable += "QueryAllPackagesPermission"
    }
}

dependencies {
    // 零依赖:不使用 androidx / compose,保持构建与产物极简
}
