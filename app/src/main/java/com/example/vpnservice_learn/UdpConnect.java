package com.example.vpnservice_learn;

import android.net.VpnService;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class UdpConnect implements PacketTool.NetworkChannel, BytesParse.Parse {

    private final BytesParse bytesParse;
    private final DatagramSocket datagramSocket;
    private final IpPacket dstIpPacket;
    private final BlockingQueue<IpPacket> queue = new LinkedBlockingQueue<>();

    private static final ExecutorService executor = Executors.newCachedThreadPool();;
    private  Future<?>  readFuture = null;
    private  Future<?>  writeFuture = null;


    public UdpConnect(VpnService vpnService, BytesParse bytesParse , IpPacket ipPacket) throws Exception {
        this.bytesParse = bytesParse;

        dstIpPacket = ipPacket;
        datagramSocket = new DatagramSocket();
        boolean protect = vpnService.protect(datagramSocket);
        datagramSocket.setSoTimeout(3000);

        readFuture = executor.submit(this::read);
        writeFuture = executor.submit(this::write);
    }

    @Override
    public void parseIpPacket(IpPacket ipPacket) {
        queue.offer(ipPacket);
    }

    private void read(){
        try{
            while (!Thread.interrupted()){

                byte[] buffer = new byte[1024];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                datagramSocket.receive(packet);
                //Push
                PacketTool.sendUdpPacket(this,buffer);

            }
        }catch (Exception e){
            close();
        }

    }

    private void write(){

        try {

            InetAddress dstAdder = dstIpPacket.getHeader().getDstAddr();
            UdpPacket udpPacket = (UdpPacket) dstIpPacket.getPayload();
            int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();


            while (!Thread.interrupted()){
                IpPacket packet = queue.take();

                UdpPacket uPacket = (UdpPacket) packet.getPayload();
                byte[] rawData = uPacket.getPayload().getRawData();

                DatagramPacket datagramPacket = new DatagramPacket(rawData, rawData.length, dstAdder, dstPort);

                datagramSocket.send(datagramPacket);
            }
        }catch (Exception e){
            close();

        }

    }

    private void close(){

        if(datagramSocket!=null){
            datagramSocket.close();
        }

        if(readFuture!=null){
            //发送中断指令
            readFuture.cancel(true);
        }

        if(writeFuture!=null){
            //发送中断指令
            writeFuture.cancel(true);
        }

        if(dstIpPacket!=null){
            bytesParse.removeKey(dstIpPacket);
        }

        if (dstIpPacket != null) {
            bytesParse.removeKey(dstIpPacket);
        }


    }

    @Override
    public AtomicInteger getSequenceNumber() {
        return null;
    }

    @Override
    public AtomicInteger getAckNumber() {
        return null;
    }

    @Override
    public void sendToVpn(byte[] packetData) {
        bytesParse.pushData(packetData);
    }

    @Override
    public InetSocketAddress getSrcAddress() {
        InetAddress dstAdder = dstIpPacket.getHeader().getDstAddr();
        UdpPacket udpPacket = (UdpPacket) dstIpPacket.getPayload();
        int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();

        return new InetSocketAddress(dstAdder, dstPort);
    }

    @Override
    public InetSocketAddress getDstAddress() {
        InetAddress srcAdder = dstIpPacket.getHeader().getSrcAddr();
        UdpPacket udpPacket = (UdpPacket) dstIpPacket.getPayload();
        int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
        return new InetSocketAddress(srcAdder, srcPort);
    }


}
