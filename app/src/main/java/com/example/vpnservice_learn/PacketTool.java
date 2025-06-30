package com.example.vpnservice_learn;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;


/**
 * TCP/UDP数据包构造工具类
 */
public final class PacketTool {
    private static final AtomicInteger IP_IDENTIFIER = new AtomicInteger(0);
    private static final byte DEFAULT_TTL = 45;
    private static final byte DEFAULT_TOS = 0;

    private PacketTool() {
    } // 工具类，防止实例化

    // TCP控制标志位常量
    private static final int TCP_SYN_FLAG = 1;
    private static final int TCP_PSH_FLAG = 2;
    private static final int TCP_FIN_FLAG = 4;
    private static final int TCP_ACK_FLAG = 8;
    private static final int TCP_RST_FLAG = 16;

    public static void sendRstPacket(NetworkChannel channel) {
        buildAndSendPacket(channel, new byte[0], TCP_RST_FLAG);
    }

    public static void sendFinPacket(NetworkChannel channel) {
        IpPacket packet = buildTcpPacket(channel, new byte[0], TCP_FIN_FLAG | TCP_ACK_FLAG);
        channel.getSequenceNumber().incrementAndGet();
        channel.sendToVpn(packet.getRawData());
    }

    public static void sendSynAckPacket(NetworkChannel channel) {
        channel.getAckNumber().incrementAndGet();
        IpPacket packet = buildTcpPacket(channel, new byte[0], TCP_SYN_FLAG | TCP_ACK_FLAG);
        channel.getSequenceNumber().incrementAndGet();
        channel.sendToVpn(packet.getRawData());
    }

    public static void sendDataPacket(NetworkChannel channel, byte[] payload) {
        IpPacket packet = buildTcpPacket(channel, payload, TCP_PSH_FLAG | TCP_ACK_FLAG);
        channel.getSequenceNumber().addAndGet(payload.length);
        channel.sendToVpn(packet.getRawData());
    }

    public static void sendAckPacket(NetworkChannel channel) {
        buildAndSendPacket(channel, new byte[0], TCP_ACK_FLAG);
    }

    public static void sendAckPacket(NetworkChannel channel, int ackIncrement) {
        channel.getAckNumber().addAndGet(ackIncrement);
        buildAndSendPacket(channel, new byte[0], TCP_ACK_FLAG);
    }

    public static void sendUdpPacket(NetworkChannel channel, byte[] payload) {
        IpPacket packet = buildUdpPacket(channel, payload);
        channel.sendToVpn(packet.getRawData());
    }

    private static void buildAndSendPacket(NetworkChannel channel,
                                           byte[] data, int flags) {
        IpPacket packet = buildTcpPacket(channel, data, flags);
        channel.sendToVpn(packet.getRawData());
    }

    private static IpPacket buildTcpPacket(NetworkChannel channel, byte[] payload, int flags) {
        TcpPacket.Builder tcpBuilder = createTcpBuilder(channel, flags);

        if (payload.length > 0) {
            tcpBuilder.payloadBuilder(new UnknownPacket.Builder().rawData(payload));
        }

        return isIPv6(channel) ?
                buildIPv6Packet(tcpBuilder, channel) :
                buildIPv4Packet(tcpBuilder, channel);
    }

    private static TcpPacket.Builder createTcpBuilder(NetworkChannel channel, int flags) {
        return new TcpPacket.Builder()
                .srcPort(getTcpPort(channel.getSrcAddress()))
                .dstPort(getTcpPort(channel.getDstAddress()))
                .sequenceNumber(channel.getSequenceNumber().get())
                .window(Short.MIN_VALUE)
                .acknowledgmentNumber(channel.getAckNumber().get())
                .syn((flags & TCP_SYN_FLAG) != 0)
                .psh((flags & TCP_PSH_FLAG) != 0)
                .fin((flags & TCP_FIN_FLAG) != 0)
                .ack((flags & TCP_ACK_FLAG) != 0)
                .rst((flags & TCP_RST_FLAG) != 0)
                .srcAddr(channel.getSrcAddress().getAddress())
                .dstAddr(channel.getDstAddress().getAddress())
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);
    }

    private static IpPacket buildUdpPacket(NetworkChannel channel, byte[] payload) {
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                .srcPort(getUdpPort(channel.getSrcAddress()))
                .dstPort(getUdpPort(channel.getDstAddress()))
                .payloadBuilder(new UnknownPacket.Builder().rawData(payload))
                .correctLengthAtBuild(true);

        return isIPv6(channel) ?
                new IpV6Packet.Builder()
                        .version(IpVersion.IPV6)
                        .srcAddr((Inet6Address) channel.getSrcAddress().getAddress())
                        .dstAddr((Inet6Address) channel.getDstAddress().getAddress())
                        .correctLengthAtBuild(true)
                        .payloadBuilder(udpBuilder)
                        .build() :
                new IpV4Packet.Builder()
                        .version(IpVersion.IPV4)
                        .ttl(DEFAULT_TTL)
                        .tos(IpV4Rfc1349Tos.newInstance(DEFAULT_TOS))
                        .protocol(IpNumber.UDP)
                        .srcAddr((Inet4Address) channel.getSrcAddress().getAddress())
                        .dstAddr((Inet4Address) channel.getDstAddress().getAddress())
                        .correctLengthAtBuild(true)
                        .correctChecksumAtBuild(true)
                        .payloadBuilder(udpBuilder)
                        .identification((short) IP_IDENTIFIER.incrementAndGet())
                        .build();
    }

    private static IpPacket buildIPv6Packet(TcpPacket.Builder tcpBuilder, NetworkChannel channel) {
        return new IpV6Packet.Builder()
                .version(IpVersion.IPV6)
                .srcAddr((Inet6Address) channel.getSrcAddress().getAddress())
                .dstAddr((Inet6Address) channel.getDstAddress().getAddress())
                .correctLengthAtBuild(true)
                .payloadBuilder(tcpBuilder)
                .trafficClass(IpV6SimpleTrafficClass.newInstance(DEFAULT_TOS))
                .flowLabel(IpV6SimpleFlowLabel.newInstance(0))
                .nextHeader(IpNumber.TCP)
                .build();
    }

    private static IpPacket buildIPv4Packet(TcpPacket.Builder tcpBuilder, NetworkChannel channel) {
        return new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .ttl(DEFAULT_TTL)
                .tos(IpV4Rfc1349Tos.newInstance(DEFAULT_TOS))
                .protocol(IpNumber.TCP)
                .srcAddr((Inet4Address) channel.getSrcAddress().getAddress())
                .dstAddr((Inet4Address) channel.getDstAddress().getAddress())
                .correctLengthAtBuild(true)
                .correctChecksumAtBuild(true)
                .payloadBuilder(tcpBuilder)
                .identification((short) IP_IDENTIFIER.incrementAndGet())
                .build();
    }

    private static boolean isIPv6(NetworkChannel channel) {
        return channel.getDstAddress().getAddress() instanceof Inet6Address;
    }

    private static TcpPort getTcpPort(InetSocketAddress address) {
        return TcpPort.getInstance((short) address.getPort());
    }

    private static UdpPort getUdpPort(InetSocketAddress address) {
        return UdpPort.getInstance((short) address.getPort());
    }

    /**
     * 表示一个可进行TCP/UDP数据包操作的网络通道
     */
    public interface NetworkChannel {
        AtomicInteger getSequenceNumber();

        AtomicInteger getAckNumber();

        void sendToVpn(byte[] packetData);

        InetSocketAddress getSrcAddress();

        InetSocketAddress getDstAddress();
    }
}