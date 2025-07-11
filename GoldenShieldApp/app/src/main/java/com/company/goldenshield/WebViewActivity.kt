package com.company.goldenshield

import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity

class WebViewActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_webview)
        val webView = findViewById<WebView>(R.id.webView)
        webView.settings.javaScriptEnabled = true

        webView.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                view?.evaluateJavascript(loadScriptFromAssets(), null)
            }
        }

        webView.loadUrl("file:///android_asset/popup.html")
    }

    private fun loadScriptFromAssets(): String {
        return assets.open("hide_content.js").bufferedReader().use { it.readText() }
    }
}
