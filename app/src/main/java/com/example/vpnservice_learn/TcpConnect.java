package com.example.vpnservice_learn;

import android.net.VpnService;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class TcpConnect implements PacketTool.NetworkChannel, BytesParse.Parse {

    private final VpnService vpnService;
    private final BytesParse bytesParse;

    private Socket socket;
    private IpPacket dstIpPacket;
    private static final ExecutorService executor = Executors.newCachedThreadPool();;

    private final BlockingQueue<Optional<IpPacket>> queue = new LinkedBlockingQueue<>();

    private  Future<?>  readFuture = null;
    private  Future<?>  writeFuture = null;



    private final AtomicBoolean srcFin = new AtomicBoolean();

    private final AtomicBoolean dstFin = new AtomicBoolean();

    private final AtomicInteger sequenceNumber = new AtomicInteger(1000);
    private final AtomicInteger ackNumber = new AtomicInteger();

    public TcpConnect(VpnService vpnService, BytesParse bytesParse) {
        this.vpnService = vpnService;
        this.bytesParse = bytesParse;
    }

    @Override
    public void parseIpPacket(IpPacket ipPacket) {

        TcpPacket tcpPacket = (TcpPacket) ipPacket.getPayload();

        boolean syn = tcpPacket.getHeader().getSyn();
        boolean fin = tcpPacket.getHeader().getFin();
        boolean psh = tcpPacket.getHeader().getPsh();
        boolean ack = tcpPacket.getHeader().getAck();
        boolean rst = tcpPacket.getHeader().getRst();

        int sequenceNumber1 = tcpPacket.getHeader().getSequenceNumber();
        int acknowledgmentNumber = tcpPacket.getHeader().getAcknowledgmentNumber();

        if (syn) {

            try {
                if(socket == null){
                    connection(ipPacket);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        } else {

            if (rst) {
                close();
                return;
            }

            if (socket == null) {

                if(!fin && !psh && ack){
                    close();
                    return;
                }

                if (fin && psh && ack){
                    this.dstIpPacket = ipPacket;
                    this.sequenceNumber.set(acknowledgmentNumber);
                    int length = tcpPacket.getPayload().getRawData().length;
                    this.ackNumber.set(sequenceNumber1+length+1);
                    PacketTool.sendRstPacket(this);
                    close();
                    return;
                }

                //rst
                this.dstIpPacket = ipPacket;
                this.ackNumber.set(sequenceNumber1);
                this.sequenceNumber.set(acknowledgmentNumber);
                PacketTool.sendRstPacket(this);
                close();
                return;
            }


            Packet payload = tcpPacket.getPayload();
            if (payload != null && payload.getRawData()!=null && payload.getRawData().length > 0) {
                queue.offer(Optional.of(ipPacket));
            } else {
                if (fin) {
                    queue.offer(Optional.ofNullable(null));
                }
            }

        }

    }

    public void connection(IpPacket ipPacket) throws Exception {
        InetAddress dstAdder = ipPacket.getHeader().getDstAddr();
        TcpPacket tcpPacket = (TcpPacket) ipPacket.getPayload();
        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
        socket = new Socket();
        socket.bind(null);
        vpnService.protect(socket);
        try {
            socket.connect(new InetSocketAddress(dstAdder, dstPort));
        } catch (IOException e) {
            close();
            throw e;
        }

        this.dstIpPacket = ipPacket;
        ackNumber.set(tcpPacket.getHeader().getSequenceNumber());

        //连接成功，发送握手
        PacketTool.sendSynAckPacket(this);

        readFuture = executor.submit(this::read);
        writeFuture = executor.submit(this::write);
    }

    private void read() {

        try (InputStream inputStream = socket.getInputStream()) {
            int len = -1;
            byte[] bt = new byte[1024];
            while ((len = (inputStream.read(bt))) > 0) {

                if(srcFin.get()){
                    break;
                }
                // push
                byte[] data = Arrays.copyOfRange(bt, 0, len);
                PacketTool.sendDataPacket(this, data);
                Thread.sleep(10);
            }

        } catch (Exception exception) {
            exception.printStackTrace();
        } finally {

            if(!socket.isClosed()){
                close();
                if (!srcFin.getAndSet(true)) {
                    //fin
                    PacketTool.sendFinPacket(this);
                }
            }
        }
    }

    private void write() {
        try {
            OutputStream outputStream = socket.getOutputStream();
            while (!Thread.interrupted()) {
                Optional<IpPacket> optional = queue.take();
                boolean fin;
                if(optional.isPresent()){
                    IpPacket packet = optional.get();
                    TcpPacket tcpPacket = (TcpPacket) packet.getPayload();

                    //防止重复写入
                    int sequenceNumber1 = tcpPacket.getHeader().getSequenceNumber();
                    if(this.ackNumber.get()!=sequenceNumber1){
                        continue;
                    }

                    byte[] rawData = tcpPacket.getPayload().getRawData();

                    outputStream.write(rawData);

                    Thread.sleep(1);//多余，为了Wireshark显示好看
                    // ack
                    PacketTool.sendAckPacket(this,rawData.length);
                    fin = tcpPacket.getHeader().getFin();

                }else{
                    fin =true;
                }
                if (fin) {
                    if (!srcFin.getAndSet(true)) {
                        //fin
                        PacketTool.sendFinPacket(this);
                        PacketTool.sendAckPacket(this,1);
                    } else {
                        PacketTool.sendAckPacket(this, 1);
                        close();
                    }
                }

            }
        } catch (Exception e) {
            close();
        }

    }

    private void close() {
        try {
            if (socket != null) {
                socket.close();
            }
        } catch (IOException ignored) {

        }

        if (dstIpPacket != null) {
            bytesParse.removeKey(dstIpPacket);
        }

        if(readFuture!=null){
            readFuture.cancel(true);
        }

        if(writeFuture!=null){
            writeFuture.cancel(true);
        }

    }

    @Override
    public AtomicInteger getSequenceNumber() {
        return sequenceNumber;
    }

    @Override
    public AtomicInteger getAckNumber() {
        return ackNumber;
    }

    @Override
    public void sendToVpn(byte[] packetData) {
        bytesParse.pushData(packetData);
    }

    @Override
    public InetSocketAddress getSrcAddress() {
        InetAddress dstAdder = dstIpPacket.getHeader().getDstAddr();
        TcpPacket tcpPacket = (TcpPacket) dstIpPacket.getPayload();
        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

        return new InetSocketAddress(dstAdder, dstPort);
    }

    @Override
    public InetSocketAddress getDstAddress() {
        InetAddress srcAdder = dstIpPacket.getHeader().getSrcAddr();
        TcpPacket tcpPacket = (TcpPacket) dstIpPacket.getPayload();
        int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
        return new InetSocketAddress(srcAdder, srcPort);
    }


}
