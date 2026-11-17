package com.example.sampleapp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.URL
import java.nio.ByteBuffer

class AdBlockVpnService : VpnService() {

    companion object {
        const val ACTION_START = "start"
        const val ACTION_STOP = "stop"
        private const val CHANNEL_ID = "adblock"
        private const val NOTIF_ID = 1
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val DNS_ADDRESS = "10.0.0.1"
        private const val BLOCKLIST_URL = "https://adaway.org/hosts.txt"
    }

    private val blocked = HashSet<String>()
    private var upstreamDns: InetAddress = InetAddress.getByName("1.1.1.1")
    private var tun: ParcelFileDescriptor? = null
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }
        startForeground(NOTIF_ID, buildNotification())
        if (worker?.isAlive != true) {
            worker = Thread { runVpn() }.also { it.start() }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        stopVpn()
    }

    private fun runVpn() {
        loadBlocklist()
        upstreamDns = systemDns()

        val pfd = Builder()
            .setSession("AdBlock")
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(DNS_ADDRESS)
            .addRoute(DNS_ADDRESS, 32)
            .establish() ?: return
        tun = pfd

        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val upstream = DatagramSocket()
        protect(upstream)
        upstream.soTimeout = 3000

        val buf = ByteArray(32767)
        try {
            while (true) {
                val len = input.read(buf)
                if (len < 0) break
                val reply = try { handlePacket(buf, len, upstream) } catch (e: Exception) { null }
                if (reply != null) output.write(reply)
            }
        } catch (e: IOException) {
            // VPN закрыт
        } finally {
            upstream.close()
        }
    }

    private fun stopVpn() {
        tun?.close()
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun handlePacket(pkt: ByteArray, len: Int, upstream: DatagramSocket): ByteArray? {
        if (len < 28) return null
        if (((pkt[0].toInt() and 0xFF) shr 4) != 4) return null
        if (pkt[9].toInt() != 17) return null
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        if (u16(pkt, ihl + 2) != 53) return null
        val clientPort = u16(pkt, ihl)
        val query = pkt.copyOfRange(ihl + 8, len)
        val (name, afterName) = readName(query, 12) ?: return null
        if (afterName + 4 > query.size) return null
        val qtype = u16(query, afterName)
        val qEnd = afterName + 4

        val reply = if (isBlocked(name)) blockedReply(query, qEnd, qtype)
            else (forward(query, upstream) ?: return null)
        return buildPacket(pkt, clientPort, reply)
    }

    private fun isBlocked(name: String): Boolean {
        var n = name
        while (true) {
            if (n in blocked) return true
            val dot = n.indexOf('.')
            if (dot < 0) return false
            n = n.substring(dot + 1)
        }
    }

    private fun blockedReply(q: ByteArray, qEnd: Int, qtype: Int): ByteArray {
        val withAnswer = qtype == 1
        val b = ByteBuffer.allocate(qEnd + (if (withAnswer) 16 else 0))
        b.put(q, 0, qEnd)
        b.put(2, (q[2].toInt() or 0x80).toByte())
        b.put(3, 0x80.toByte())
        b.putShort(6, (if (withAnswer) 1 else 0).toShort())
        b.putShort(8, 0)
        b.putShort(10, 0)
        if (withAnswer) {
            b.putShort(0xC00C.toShort())
            b.putShort(1)
            b.putShort(1)
            b.putInt(60)
            b.putShort(4)
            b.putInt(0)
        }
        return b.array()
    }

    private fun forward(query: ByteArray, upstream: DatagramSocket): ByteArray? = try {
        upstream.send(DatagramPacket(query, query.size, upstreamDns, 53))
        val buf = ByteArray(1500)
        val p = DatagramPacket(buf, buf.size)
        upstream.receive(p)
        buf.copyOf(p.length)
    } catch (e: IOException) {
        null
    }

    private fun buildPacket(pkt: ByteArray, clientPort: Int, dns: ByteArray): ByteArray {
        val total = 28 + dns.size
        val b = ByteBuffer.allocate(total)
        b.put(0x45.toByte())
        b.put(0.toByte())
        b.putShort(total.toShort())
        b.putShort(0)
        b.putShort(0x4000.toShort())
        b.put(64.toByte())
        b.put(17.toByte())
        b.putShort(0)
        b.put(byteArrayOf(10, 0, 0, 1))
        b.put(pkt, 12, 4)
        b.putShort(53)
        b.putShort(clientPort.toShort())
        b.putShort((8 + dns.size).toShort())
        b.putShort(0)
        b.put(dns)
        val out = b.array()
        val sum = checksum(out, 0, 20)
        out[10] = (sum shr 8).toByte()
        out[11] = sum.toByte()
        return out
    }

    private fun readName(q: ByteArray, start: Int): Pair<String, Int>? {
        val parts = ArrayList<String>()
        var i = start
        while (i < q.size) {
            val len = q[i].toInt() and 0xFF
            if (len == 0) return Pair(parts.joinToString(".").lowercase(), i + 1)
            if ((len and 0xC0) != 0 || i + 1 + len > q.size) return null
            parts.add(String(q, i + 1, len, Charsets.US_ASCII))
            i += len + 1
        }
        return null
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        while (i < off + len) {
            sum += u16(b, i)
            i += 2
        }
        while (sum > 0xFFFF) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    private fun systemDns(): InetAddress {
        val cm = getSystemService(ConnectivityManager::class.java)
        val net = cm.activeNetwork ?: return upstreamDns
        return cm.getLinkProperties(net)?.dnsServers
            ?.firstOrNull { it is Inet4Address } ?: upstreamDns
    }

    private fun loadBlocklist() {
        try {
            URL(BLOCKLIST_URL).openStream().bufferedReader().useLines { lines ->
                for (line in lines) {
                    val p = line.trim().split(Regex("\\s+"))
                    if (p.size >= 2 && (p[0] == "0.0.0.0" || p[0] == "127.0.0.1")) {
                        blocked.add(p[1].lowercase())
                    }
                }
            }
        } catch (e: IOException) {
            // нет интернета: работаем без списка
        }
    }

    private fun buildNotification(): Notification {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "Блокировка рекламы", NotificationManager.IMPORTANCE_LOW)
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Блокировка рекламы работает")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
    }
}
