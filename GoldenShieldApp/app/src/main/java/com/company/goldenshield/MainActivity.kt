package com.company.goldenshield

import android.content.Intent
import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import okhttp3.*
import org.json.JSONArray
import java.io.IOException

class MainActivity : AppCompatActivity() {
    private val client = OkHttpClient()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val refreshBtn = findViewById<Button>(R.id.refreshButton)
        val historyList = findViewById<ListView>(R.id.historyList)

        refreshBtn.setOnClickListener {
            refreshBlockList()
        }

        findViewById<Button>(R.id.browserButton).setOnClickListener {
            startActivity(Intent(this, WebViewActivity::class.java))
        }

        loadBrowsingHistory(historyList)
    }

    private fun refreshBlockList() {
        val request = Request.Builder()
            .url("http://10.0.2.2:5000/blocked_sites") // Adjust for real IP in production
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                runOnUiThread {
                    Toast.makeText(this@MainActivity, "Refresh failed", Toast.LENGTH_SHORT).show()
                }
            }

            override fun onResponse(call: Call, response: Response) {
                runOnUiThread {
                    if (response.isSuccessful) {
                        Toast.makeText(this@MainActivity, "Block list refreshed", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this@MainActivity, "Server error: ${response.code}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        })
    }

    private fun loadBrowsingHistory(listView: ListView) {
        val request = Request.Builder()
            .url("http://10.0.2.2:5000/user_dashboard")
            .build()

        client.newCall(request).enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {}

            override fun onResponse(call: Call, response: Response) {
                val historyItems = mutableListOf<String>()
                response.body?.string()?.let {
                    val json = JSONArray(it)
                    for (i in 0 until json.length()) {
                        historyItems.add(json.getString(i))
                    }
                }

                runOnUiThread {
                    listView.adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_list_item_1, historyItems)
                }
            }
        })
    }
}
