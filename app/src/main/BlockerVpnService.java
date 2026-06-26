package com.siteblocker.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONException;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.HashSet;
import java.util.Set;

public class BlockerVpnService extends VpnService {

    public static final String ACTION_START = "START";
    public static final String ACTION_STOP  = "STOP";
    private static final String TAG         = "BlockerVPN";
    private static final String CHANNEL_ID  = "blocker_channel";

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;
    private volatile boolean running = false;
    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;  // Keeps WiFi alive like PersonalDNSfilter does

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || ACTION_START.equals(intent.getAction())) {
            startVpn();
            return START_STICKY;
        }
        if (ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }
        return START_STICKY;
    }

    private void startVpn() {
        // Clean up previous run
        running = false;
        if (vpnThread != null) vpnThread.interrupt();
        try { if (vpnInterface != null) vpnInterface.close(); } catch (Exception ignored) {}
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();

        createNotificationChannel();

        // Foreground notification — prevents Samsung from killing the service
        PendingIntent pi = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class),
                PendingIntent.FLAG_IMMUTABLE);

        Notification notif = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Site Blocker Active")
                .setContentText("Blocking websites — tap to manage")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();

        // Use typed foreground service for Android 14+ — same fix as PersonalDNSfilter
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(1, notif, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        } else {
            startForeground(1, notif);
        }

        // Wake lock + WiFi lock keeps CPU and WiFi alive on Samsung
        PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "SiteBlocker:VpnLock");
        wakeLock.acquire();

        WifiManager wm = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
        wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "SiteBlocker:WifiLock");
        wifiLock.acquire();

        try {
            vpnInterface = new Builder()
                    .setSession("SiteBlocker")
                    .addAddress("10.0.0.2", 32)
                    .addDnsServer("10.0.0.1")   // Our fake DNS handled locally
                    .addRoute("10.0.0.1", 32)
                    .setMtu(1500)
                    .establish();

            if (vpnInterface == null) {
                Log.e(TAG, "VPN establish returned null — permission denied?");
                stopSelf();
                return;
            }
        } catch (Exception e) {
            Log.e(TAG, "VPN establish failed: " + e.getMessage());
            stopSelf();
            return;
        }

        running = true;
        vpnThread = new Thread(this::runVpnLoop, "VpnThread");
        vpnThread.setDaemon(false);
        vpnThread.start();
        Log.d(TAG, "VPN started successfully");
    }

    private void runVpnLoop() {
        FileInputStream  in  = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());
        byte[] buf = new byte[32767];

        while (running) {
            try {
                int len = in.read(buf);
                if (len <= 0) { sleep(10); continue; }

                String domain = extractDnsDomain(buf, len);
                if (domain == null) continue;

                if (isBlocked(domain)) {
                    Log.d(TAG, "BLOCKED: " + domain);
                    // Send NXDOMAIN response so browser shows error immediately
                    byte[] nxdomain = buildNxDomainResponse(buf, len);
                    if (nxdomain != null) out.write(nxdomain);
                } else {
                    forwardDns(buf, len, out);
                }
            } catch (IOException e) {
                if (running) Log.e(TAG, "Loop error: " + e.getMessage());
                sleep(100);
            } catch (Exception e) {
                if (running) Log.e(TAG, "Unexpected error: " + e.getMessage());
                sleep(100);
            }
        }
    }

    /**
     * Sends NXDOMAIN (domain not found) reply so browser fails fast instead of timing out.
     */
    private byte[] buildNxDomainResponse(byte[] req, int len) {
        try {
            int ipHeaderLen = (req[0] & 0x0F) * 4;
            int dnsOffset   = ipHeaderLen + 8;
            int dnsLen      = len - dnsOffset;
            if (dnsLen < 12) return null;

            // Copy DNS query, set QR=1 (response) and RCODE=3 (NXDOMAIN)
            byte[] dnsResp = new byte[dnsLen];
            System.arraycopy(req, dnsOffset, dnsResp, 0, dnsLen);
            dnsResp[2] = (byte) 0x81; // QR=1, Opcode=0, AA=0, TC=0, RD=1
            dnsResp[3] = (byte) 0x83; // RA=1, RCODE=3 (NXDOMAIN)

            return buildIpUdpPacket(req, ipHeaderLen, dnsResp, dnsLen);
        } catch (Exception e) {
            return null;
        }
    }

    /** Forwards DNS packet to 8.8.8.8 and returns the response. */
    private void forwardDns(byte[] req, int len, FileOutputStream out) {
        try {
            int ipHeaderLen = (req[0] & 0x0F) * 4;
            int dnsOffset   = ipHeaderLen + 8;
            int dnsLen      = len - dnsOffset;
            if (dnsLen <= 0) return;

            byte[] dnsData = new byte[dnsLen];
            System.arraycopy(req, dnsOffset, dnsData, 0, dnsLen);

            DatagramSocket socket = new DatagramSocket();
            protect(socket);  // Bypass VPN so we can reach real internet
            socket.setSoTimeout(3000);

            InetAddress dns = InetAddress.getByName("8.8.8.8");
            socket.send(new DatagramPacket(dnsData, dnsLen, dns, 53));

            byte[] resp = new byte[4096];
            DatagramPacket recv = new DatagramPacket(resp, resp.length);
            socket.receive(recv);
            socket.close();

            byte[] full = buildIpUdpPacket(req, ipHeaderLen, resp, recv.getLength());
            if (full != null) out.write(full);

        } catch (Exception e) {
            Log.d(TAG, "DNS forward error: " + e.getMessage());
        }
    }

    /** Wraps DNS response in IP+UDP packet to send back through VPN interface. */
    private byte[] buildIpUdpPacket(byte[] orig, int ipHeaderLen, byte[] dnsResp, int dnsRespLen) {
        if (orig.length < ipHeaderLen + 8) return null;
        int total = 20 + 8 + dnsRespLen;
        byte[] pkt = new byte[total];

        // IP header
        pkt[0] = 0x45;
        pkt[2] = (byte) ((total >> 8) & 0xFF);
        pkt[3] = (byte) (total & 0xFF);
        pkt[4] = orig[4]; pkt[5] = orig[5];
        pkt[8] = 64; pkt[9] = 17;
        System.arraycopy(orig, 16, pkt, 12, 4); // swap src/dst IP
        System.arraycopy(orig, 12, pkt, 16, 4);
        setIpChecksum(pkt);

        // UDP header — swap ports
        pkt[20] = orig[ipHeaderLen + 2]; pkt[21] = orig[ipHeaderLen + 3];
        pkt[22] = orig[ipHeaderLen];     pkt[23] = orig[ipHeaderLen + 1];
        int udpLen = 8 + dnsRespLen;
        pkt[24] = (byte) ((udpLen >> 8) & 0xFF);
        pkt[25] = (byte) (udpLen & 0xFF);

        System.arraycopy(dnsResp, 0, pkt, 28, dnsRespLen);
        return pkt;
    }

    private void setIpChecksum(byte[] h) {
        h[10] = 0; h[11] = 0;
        int s = 0;
        for (int i = 0; i < 20; i += 2)
            s += ((h[i] & 0xFF) << 8) | (h[i + 1] & 0xFF);
        while ((s >> 16) != 0) s = (s & 0xFFFF) + (s >> 16);
        s = ~s;
        h[10] = (byte) ((s >> 8) & 0xFF);
        h[11] = (byte) (s & 0xFF);
    }

    /** Parses DNS query packet and returns the queried domain name. */
    private String extractDnsDomain(byte[] data, int len) {
        try {
            int ipHeaderLen = (data[0] & 0x0F) * 4;
            if (data[9] != 17) return null; // not UDP
            int dstPort = ((data[ipHeaderLen + 2] & 0xFF) << 8) | (data[ipHeaderLen + 3] & 0xFF);
            if (dstPort != 53) return null; // not DNS

            int dnsOffset = ipHeaderLen + 8;
            if (len < dnsOffset + 12) return null;
            // Check it's a query (QR bit = 0)
            if ((data[dnsOffset + 2] & 0x80) != 0) return null;

            StringBuilder domain = new StringBuilder();
            int pos = dnsOffset + 12;
            while (pos < len) {
                int labelLen = data[pos++] & 0xFF;
                if (labelLen == 0) break;
                if (domain.length() > 0) domain.append(".");
                for (int i = 0; i < labelLen && pos < len; i++)
                    domain.append((char) (data[pos++] & 0xFF));
            }
            return domain.length() > 0 ? domain.toString().toLowerCase() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Checks if domain or any parent domain is in the block list. */
    private boolean isBlocked(String domain) {
        Set<String> blocked = getBlockedSites();
        if (blocked.contains(domain)) return true;
        for (String site : blocked) {
            if (domain.endsWith("." + site)) return true;
        }
        return false;
    }

    private Set<String> getBlockedSites() {
        Set<String> set = new HashSet<>();
        SharedPreferences prefs = getSharedPreferences("siteblocker", MODE_PRIVATE);
        try {
            JSONArray arr = new JSONArray(prefs.getString("blocked_sites", "[]"));
            for (int i = 0; i < arr.length(); i++) set.add(arr.getString(i));
        } catch (JSONException ignored) {}
        return set;
    }

    private void stopVpn() {
        running = false;
        if (vpnThread != null) vpnThread.interrupt();
        try { if (vpnInterface != null) vpnInterface.close(); } catch (Exception ignored) {}
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        if (wifiLock != null && wifiLock.isHeld()) wifiLock.release();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        running = false;
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        if (wifiLock != null && wifiLock.isHeld()) wifiLock.release();
    }

    private void createNotificationChannel() {
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "Site Blocker", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Shows when site blocking is active");
        getSystemService(NotificationManager.class).createNotificationChannel(ch);
    }

    private void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }
}
