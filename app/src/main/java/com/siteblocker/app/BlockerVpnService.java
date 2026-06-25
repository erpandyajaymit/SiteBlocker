package com.siteblocker.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.system.OsConstants;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONException;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;

/**
 * Local VPN service. Reads DNS packets and drops queries for blocked sites.
 * No traffic leaves the device — everything is handled locally.
 */
public class BlockerVpnService extends VpnService {

    public static final String ACTION_START = "START";
    public static final String ACTION_STOP = "STOP";
    private static final String TAG = "BlockerVPN";
    private static final String CHANNEL_ID = "blocker_channel";

    private ParcelFileDescriptor vpnInterface;
    private Thread vpnThread;
    private volatile boolean running = false;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_NOT_STICKY;

        if (ACTION_STOP.equals(intent.getAction())) {
            stopVpn();
            return START_NOT_STICKY;
        }

        if (ACTION_START.equals(intent.getAction())) {
            startVpn();
        }
        return START_STICKY;
    }

    private void startVpn() {
        createNotificationChannel();
        Notification notif = new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Site Blocker Active")
                .setContentText("Blocking is ON")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .build();
        startForeground(1, notif);

        // Build the VPN interface — only routes DNS traffic (port 53)
        Builder builder = new Builder()
                .setSession("SiteBlocker")
                .addAddress("10.0.0.2", 32)
                .addDnsServer("8.8.8.8")
                .addRoute("8.8.8.8", 32)    // Only route DNS server traffic through VPN
                .addRoute("8.8.4.4", 32)
                .setMtu(1500)
                .allowFamily(OsConstants.AF_INET);

        try {
            vpnInterface = builder.establish();
        } catch (Exception e) {
            Log.e(TAG, "VPN establish failed", e);
            return;
        }

        running = true;
        vpnThread = new Thread(this::runVpnLoop, "VpnThread");
        vpnThread.start();
    }

    private void runVpnLoop() {
        FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor());
        FileOutputStream out = new FileOutputStream(vpnInterface.getFileDescriptor());

        ByteBuffer packet = ByteBuffer.allocate(32767);

        while (running) {
            try {
                packet.clear();
                int len = in.read(packet.array());
                if (len <= 0) continue;

                packet.limit(len);

                // Parse IP packet to get DNS query domain
                String domain = extractDnsDomain(packet.array(), len);

                if (domain != null && isBlocked(domain)) {
                    // Drop packet — don't forward, don't reply.
                    // Browser will get a timeout and show "site not reachable"
                    Log.d(TAG, "BLOCKED: " + domain);
                    continue;
                }

                // Forward non-blocked DNS to real DNS server and return response
                forwardDns(packet.array(), len, out);

            } catch (IOException e) {
                if (running) Log.e(TAG, "VPN loop error", e);
            }
        }
    }

    /**
     * Forwards DNS packet to 8.8.8.8:53 via UDP and writes response back.
     */
    private void forwardDns(byte[] packetData, int len, FileOutputStream out) {
        try {
            // Extract DNS payload (skip IP header 20 bytes + UDP header 8 bytes)
            int ipHeaderLen = (packetData[0] & 0x0F) * 4;
            int dnsOffset = ipHeaderLen + 8;
            int dnsLen = len - dnsOffset;
            if (dnsLen <= 0) return;

            byte[] dnsData = new byte[dnsLen];
            System.arraycopy(packetData, dnsOffset, dnsData, 0, dnsLen);

            // Send to real DNS
            DatagramSocket socket = new DatagramSocket();
            protect(socket); // Allow this socket to bypass VPN
            InetAddress dnsServer = InetAddress.getByName("8.8.8.8");
            DatagramPacket send = new DatagramPacket(dnsData, dnsLen, dnsServer, 53);
            socket.send(send);

            // Read response
            byte[] resp = new byte[4096];
            DatagramPacket recv = new DatagramPacket(resp, resp.length);
            socket.setSoTimeout(3000);
            socket.receive(recv);
            socket.close();

            // Build response IP+UDP packet back to VPN interface
            byte[] full = buildIpUdpPacket(
                    packetData, ipHeaderLen,
                    resp, recv.getLength()
            );
            if (full != null) out.write(full);

        } catch (Exception e) {
            Log.d(TAG, "DNS forward error: " + e.getMessage());
        }
    }

    /**
     * Builds a minimal IP+UDP packet wrapping the DNS response.
     */
    private byte[] buildIpUdpPacket(byte[] origPacket, int ipHeaderLen, byte[] dnsResp, int dnsRespLen) {
        if (origPacket.length < ipHeaderLen + 8) return null;

        int totalLen = 20 + 8 + dnsRespLen;
        byte[] pkt = new byte[totalLen];

        // IP header
        pkt[0] = 0x45; // Version=4, IHL=5
        pkt[1] = 0;
        pkt[2] = (byte) ((totalLen >> 8) & 0xFF);
        pkt[3] = (byte) (totalLen & 0xFF);
        pkt[4] = origPacket[4]; pkt[5] = origPacket[5]; // ID
        pkt[6] = 0; pkt[7] = 0; // Flags
        pkt[8] = 64; // TTL
        pkt[9] = 17; // Protocol UDP
        // Swap src/dst IP from original packet
        System.arraycopy(origPacket, 16, pkt, 12, 4); // dst -> src
        System.arraycopy(origPacket, 12, pkt, 16, 4); // src -> dst
        // IP checksum
        setIpChecksum(pkt);

        // UDP header
        pkt[20] = origPacket[ipHeaderLen + 2]; pkt[21] = origPacket[ipHeaderLen + 3]; // dst port -> src
        pkt[22] = origPacket[ipHeaderLen];     pkt[23] = origPacket[ipHeaderLen + 1]; // src port -> dst
        int udpLen = 8 + dnsRespLen;
        pkt[24] = (byte) ((udpLen >> 8) & 0xFF);
        pkt[25] = (byte) (udpLen & 0xFF);
        pkt[26] = 0; pkt[27] = 0; // Checksum (optional for IPv4)

        // DNS payload
        System.arraycopy(dnsResp, 0, pkt, 28, dnsRespLen);
        return pkt;
    }

    private void setIpChecksum(byte[] hdr) {
        hdr[10] = 0; hdr[11] = 0;
        int sum = 0;
        for (int i = 0; i < 20; i += 2)
            sum += ((hdr[i] & 0xFF) << 8) | (hdr[i + 1] & 0xFF);
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        sum = ~sum;
        hdr[10] = (byte) ((sum >> 8) & 0xFF);
        hdr[11] = (byte) (sum & 0xFF);
    }

    /**
     * Extracts domain name from a DNS query packet.
     * Returns null if not a DNS query or can't parse.
     */
    private String extractDnsDomain(byte[] data, int len) {
        try {
            int ipHeaderLen = (data[0] & 0x0F) * 4;
            int protocol = data[9] & 0xFF;
            if (protocol != 17) return null; // Not UDP

            int dstPort = ((data[ipHeaderLen + 2] & 0xFF) << 8) | (data[ipHeaderLen + 3] & 0xFF);
            if (dstPort != 53) return null; // Not DNS

            int dnsOffset = ipHeaderLen + 8;
            if (len < dnsOffset + 12) return null;

            int flags = ((data[dnsOffset + 2] & 0xFF) << 8) | (data[dnsOffset + 3] & 0xFF);
            if ((flags & 0x8000) != 0) return null; // It's a response, not a query

            // Parse question section — starts at dnsOffset + 12
            StringBuilder domain = new StringBuilder();
            int pos = dnsOffset + 12;
            while (pos < len) {
                int labelLen = data[pos] & 0xFF;
                if (labelLen == 0) break;
                if (domain.length() > 0) domain.append(".");
                pos++;
                for (int i = 0; i < labelLen && pos < len; i++, pos++)
                    domain.append((char) (data[pos] & 0xFF));
            }
            return domain.length() > 0 ? domain.toString().toLowerCase() : null;

        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Check if domain matches any blocked site.
     * Handles subdomains: blocking "youtube.com" also blocks "www.youtube.com"
     */
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
        String json = prefs.getString("blocked_sites", "[]");
        try {
            JSONArray arr = new JSONArray(json);
            for (int i = 0; i < arr.length(); i++) set.add(arr.getString(i));
        } catch (JSONException ignored) {}
        return set;
    }

    private void stopVpn() {
        running = false;
        if (vpnThread != null) vpnThread.interrupt();
        try {
            if (vpnInterface != null) vpnInterface.close();
        } catch (IOException ignored) {}
        stopForeground(true);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        running = false;
    }

    private void createNotificationChannel() {
        NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID, "Site Blocker", NotificationManager.IMPORTANCE_LOW);
        getSystemService(NotificationManager.class).createNotificationChannel(ch);
    }
}
