package com.example.nonative

import android.app.Activity
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Minimal white screen: no buttons, no chrome. Detection starts automatically
 * on entry — "Dirty" when root / integrity signals are found, "Clean" otherwise,
 * with a one-line hint underneath.
 */
class MainActivity : Activity() {

    private lateinit var resultView: TextView
    private lateinit var hintView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.WHITE)
        }
        resultView = TextView(this).apply {
            gravity = Gravity.CENTER
            textSize = 72f
            setTextColor(Color.BLACK)
        }
        hintView = TextView(this).apply {
            gravity = Gravity.CENTER
            textSize = 14f
            setTextColor(0xFF888888.toInt())
            setPadding(48, 40, 48, 0)
        }
        root.addView(resultView)
        root.addView(hintView)
        setContentView(root)

        hideSystemBars()
        hintView.text = "Scanning…"
        Thread {
            val report = RootDetector.detect(applicationContext)
            runOnUiThread { show(report) }
        }.start()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) hideSystemBars()
    }

    private fun show(report: RootDetector.Report) {
        // "Dirty" = root / integrity anomaly detected (red), "Clean" = clean (green)
        if (report.detected) {
            resultView.text = "Dirty"
            resultView.setTextColor(0xFFD32F2F.toInt())
        } else {
            resultView.text = "Clean"
            resultView.setTextColor(0xFF388E3C.toInt())
        }
        hintView.text = buildString {
            if (report.detected) {
                append("Root / integrity anomaly detected (${report.dangers.size})")
                val cats = report.dangers.map { it.category }.distinct()
                if (cats.isNotEmpty()) append("\n").append(cats.joinToString(", "))
            } else {
                append("No root detected, environment looks clean")
            }
            if (report.warnings.isNotEmpty()) {
                val wcats = report.warnings.map { it.category }.distinct()
                append("\nSuspicious (${report.warnings.size}): ").append(wcats.joinToString(", "))
            }
        }
    }

    private fun hideSystemBars() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false)
            window.insetsController?.hide(WindowInsets.Type.statusBars() or WindowInsets.Type.navigationBars())
        } else {
            @Suppress("DEPRECATION")
            window.decorView.systemUiVisibility = (View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                    or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    or View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                    or View.SYSTEM_UI_FLAG_FULLSCREEN
                    or View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY)
        }
    }
}
