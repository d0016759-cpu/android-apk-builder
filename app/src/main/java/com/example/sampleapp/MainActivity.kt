package com.example.sampleapp

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {

    private lateinit var statusText: TextView
    private lateinit var toggleButton: Button
    private var running = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        statusText = TextView(this).apply { textSize = 20f }
        toggleButton = Button(this).apply { setOnClickListener { toggle() } }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 200, 48, 48)
            addView(statusText)
            addView(toggleButton)
        })
        updateUi()
    }

    private fun toggle() {
        if (running) {
            startService(Intent(this, AdBlockVpnService::class.java).setAction(AdBlockVpnService.ACTION_STOP))
            running = false
            updateUi()
        } else {
            val permission = VpnService.prepare(this)
            if (permission != null) {
                startActivityForResult(permission, 1)
            } else {
                startVpn()
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 1 && resultCode == RESULT_OK) startVpn()
    }

    private fun startVpn() {
        val intent = Intent(this, AdBlockVpnService::class.java).setAction(AdBlockVpnService.ACTION_START)
        startForegroundService(intent)
        running = true
        updateUi()
    }

    private fun updateUi() {
        statusText.text = if (running) "Блокировка работает" else "Блокировка выключена"
        toggleButton.text = if (running) "Выключить" else "Включить"
    }
}
