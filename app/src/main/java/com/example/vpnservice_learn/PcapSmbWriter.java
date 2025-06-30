package com.example.vpnservice_learn;

import android.net.VpnService;
import android.util.Log;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.EnumSet;
import java.util.Locale;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.net.SocketFactory;

public class PcapSmbWriter implements Closeable {
    private static final String TAG = "PcapSmbWriter";

    private static final String SMB_SERVER = "192.168.10.195";
    private static final String SMB_SHARE = "share";
    private static final String SMB_USER = "test";
    private static final String SMB_PASS = "123";

    private final VpnService vpnService;
    private SMBClient smbClient;
    private Connection connection;
    private DiskShare share;
    private File file;

    private final BlockingQueue<Object[]> packetQueue = new LinkedBlockingQueue<>();
    private volatile boolean isRunning = false;
    private Thread writeThread;
    private boolean headerWritten = false;

    public PcapSmbWriter(VpnService vpnService) {
        this.vpnService = vpnService;
    }

    public void start() throws IOException {
        if (isRunning) return;

        SmbConfig config = SmbConfig.builder()
                .withSocketFactory(new SocketFactory() {
                    @Override
                    public Socket createSocket() throws IOException {
                        Socket socket = new Socket();
                        protectSocket(socket);
                        return socket;
                    }

                    @Override
                    public Socket createSocket(String host, int port) throws IOException {
                        Socket socket = new Socket();
                        protectSocket(socket);
                        socket.connect(new InetSocketAddress(host, port));
                        return socket;
                    }

                    @Override
                    public Socket createSocket(java.net.InetAddress address, int port) throws IOException {
                        Socket socket = new Socket();
                        protectSocket(socket);
                        socket.connect(new InetSocketAddress(address, port));
                        return socket;
                    }

                    @Override
                    public Socket createSocket(String host, int port, java.net.InetAddress localAddr, int localPort) throws IOException {
                        Socket socket = new Socket(localAddr, localPort);
                        protectSocket(socket);
                        socket.connect(new InetSocketAddress(host, port));
                        return socket;
                    }

                    @Override
                    public Socket createSocket(java.net.InetAddress address, int port, java.net.InetAddress localAddr, int localPort) throws IOException {
                        Socket socket = new Socket(localAddr, localPort);
                        protectSocket(socket);
                        socket.connect(new InetSocketAddress(address, port));
                        return socket;
                    }

                    private void protectSocket(Socket socket) throws IOException {
                        socket.bind(null);
                        if (!vpnService.protect(socket)) {
                            throw new IOException("VPN protect failed");
                        }
                    }
                })
                .build();

        smbClient = new SMBClient(config);
        connection = smbClient.connect(SMB_SERVER);
        Session session = connection.authenticate(new AuthenticationContext(SMB_USER, SMB_PASS.toCharArray(), null));
        share = (DiskShare) session.connectShare(SMB_SHARE);
        String time = new SimpleDateFormat("HHmmss", Locale.getDefault())
                .format(new Date());
        file = share.openFile(
                "vpn_"+time+".pcap",
                EnumSet.of(AccessMask.GENERIC_WRITE, AccessMask.FILE_READ_ATTRIBUTES),
                null,
                SMB2ShareAccess.ALL,
                SMB2CreateDisposition.FILE_OPEN_IF,
                null
        );

        // 检查是否需要写入 PCAP Header
        long offset = file.getFileInformation().getStandardInformation().getEndOfFile();
        if (offset == 0 && !headerWritten) {
            file.write(generatePcapHeader(), 0);
            headerWritten = true;
        } else {
            headerWritten = true;
        }

        isRunning = true;
        writeThread = new Thread(this::runWriterLoop, "SmbPcapWriterThread");
        writeThread.start();
        Log.i(TAG, "PcapSmbWriter started");
    }

    public void addQueue(byte[] packetData) {
        if (!isRunning || packetData == null || packetData.length == 0) return;
        long now = System.currentTimeMillis();
        packetQueue.offer(new Object[]{now, packetData});
    }


    private void runWriterLoop() {
        try {
            while (isRunning || !packetQueue.isEmpty()) {
                Object[] take = packetQueue.take();
                long time = (Long) take[0];
                byte[] packetData = (byte[]) take[1];

                int version = (packetData[0] >> 4) & 0xF;
                EtherType etherType;

                if (version == 4) {
                    etherType = EtherType.IPV4;
                } else if (version == 6) {
                    etherType = EtherType.IPV6;
                } else {
                    Log.w(TAG, "未知的 IP 协议版本: " + version);
                    return; // 忽略无法识别的包
                }

                EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder();
                etherBuilder
                        .dstAddr(MacAddress.getByName("45:00:00:00:00:01"))
                        .srcAddr(MacAddress.getByName("45:00:00:00:00:02"))
                        .type(etherType)
                        .payloadBuilder(new UnknownPacket.Builder().rawData(packetData))
                        .paddingAtBuild(true);

                EthernetPacket ethernetPacket = etherBuilder.build();

                byte[] rawData = ethernetPacket.getRawData();

                byte[] array = ByteBuffer.allocate(16 + rawData.length)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .putInt((int) (time / 1000))            // timestamp seconds
                        .putInt((int) ((time % 1000) * 1000))   // timestamp microseconds
                        .putInt(rawData.length)             // captured length
                        .putInt(rawData.length)             // actual length
                        .put(rawData)
                        .array();

                long offset = file.getFileInformation().getStandardInformation().getEndOfFile();
                file.write(array, offset);
            }
        } catch (Exception e) {
            Log.e(TAG, "写入线程异常", e);
        }
    }

    private byte[] generatePcapHeader() {
        return ByteBuffer.allocate(24)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(0xa1b2c3d4) // Magic Number
                .putShort((short) 2) // Major version
                .putShort((short) 4) // Minor version
                .putInt(0) // GMT to local correction
                .putInt(0) // Accuracy of timestamps
                .putInt(65535) // Max length of captured packets, in octets
                .putInt(1) // Data link type: LINKTYPE_ETHERNET = 1
                .array();
    }


    @Override
    public void close() {
        isRunning = false;
        if (writeThread != null) {
            try {
                writeThread.join(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        try {
            if (file != null) file.close();
            if (share != null) share.close();
            if (connection != null) connection.close();
            if (smbClient != null) smbClient.close();
        } catch (Exception e) {
            Log.w(TAG, "关闭资源失败", e);
        }

        Log.i(TAG, "PcapSmbWriter closed");
    }
}
