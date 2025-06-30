package com.example.vpnservice_learn;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpSelector;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TransportPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class BytesParse implements Runnable {

    private final BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    private final ExecutorService executor = Executors.newFixedThreadPool(3);
    private final MyVpnService myVpnService;
    private final Map<String, Parse> connectionMap = new ConcurrentHashMap<>();
    private final PcapSmbWriter pcapSmbWriter;


    public BytesParse(MyVpnService myVpnService) {
        this.myVpnService = myVpnService;
        this.pcapSmbWriter = new PcapSmbWriter(myVpnService);
    }

    @Override
    public void run() {

        // 写入PC共享文件
        executor.submit(()->{
            try {
                pcapSmbWriter.start();
            } catch (Exception e) {
               e.printStackTrace();
            }
        });

        // 读线程
        executor.submit(() -> {
            try (FileInputStream fileInputStream = new FileInputStream(myVpnService.descriptor.getFileDescriptor())) {
                byte[] bt = new byte[1024 * 20];
                int len;
                while ((len = fileInputStream.read(bt)) != -1) {
                    if (len == 0) continue;
                    parseData(bt, len);
                }
            } catch (Exception ignored) {
                pcapSmbWriter.close();
            }
        });

        // 写线程
        executor.submit(() -> {

            try (FileOutputStream fileOutputStream = new FileOutputStream(myVpnService.descriptor.getFileDescriptor())) {
                while (!Thread.interrupted()) {
                    byte[] take = queue.take();

                    // 写入PC共享文件
                    pcapSmbWriter.addQueue(take);

                    fileOutputStream.write(take);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private void parseData(byte[] data, int len) {
        try {
            Packet packet = IpSelector.newPacket(data, 0, len);
            if (packet instanceof IpPacket ipPacket) {
                String key = getKey(ipPacket);
                if (key == null) return;

                if (!connectionMap.containsKey(key)) {
                    if (ipPacket.getHeader().getProtocol() == IpNumber.TCP) {
                        TcpConnect tcpConnect = new TcpConnect(myVpnService, this);
                        connectionMap.putIfAbsent(key, tcpConnect);
                    } else if (ipPacket.getHeader().getProtocol() == IpNumber.UDP) {
                        UdpConnect udpConnect = new UdpConnect(myVpnService, this, ipPacket);
                        connectionMap.putIfAbsent(key, udpConnect);
                    }
                }

                Parse parse = connectionMap.get(key);
                if (parse != null) {
                    parse.parseIpPacket(ipPacket);
                }
            }

            // 写入PC共享文件
            byte[] d = Arrays.copyOfRange(data, 0, len);
            pcapSmbWriter.addQueue(d);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("ReadData parseData 解析包异常: " + e.getMessage());
        }
    }

    public String getKey(IpPacket ipPacket) {
        Packet payload = ipPacket.getPayload();
        // 明确只处理TCP/UDP
        if (payload instanceof TcpPacket tcpPacket) {
            return "tcp:" + tcpPacket.getHeader().getSrcPort().valueAsInt();
        } else if (payload instanceof UdpPacket udpPacket) {
            return "udp:" + udpPacket.getHeader().getSrcPort().valueAsInt();
        } else {
            // 其他协议返回null或抛出异常
            return null;
        }
    }

    public void removeKey(IpPacket ipPacket) {
        String key = getKey(ipPacket);
        if (key != null) {
            connectionMap.remove(key);
        }
    }

    public void pushData(byte[] data) {
        queue.offer(data);
    }

    interface Parse {
        void parseIpPacket(IpPacket ipPacket);
    }
}
