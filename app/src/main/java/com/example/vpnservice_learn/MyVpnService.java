package com.example.vpnservice_learn;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import java.io.IOException;
import java.util.Objects;

/**
 * 自定义VPN服务，继承自Android系统的VpnService
 * 负责建立和管理VPN连接
 */
public class MyVpnService extends VpnService {
    // VPN隧道接口的文件描述符，用于管理VPN连接
    public ParcelFileDescriptor descriptor;
    private Thread thread;
    private PendingIntent pendingIntent;
    /**
     * 服务启动命令处理
     *
     * @param intent 包含操作指令("start"或"stop")
     * @return START_STICKY 表示服务被异常终止后会自动重启
     */
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        switch (Objects.requireNonNull(intent.getStringExtra("status"))) {
            case "start":
                setupVpn(); // 建立VPN连接
                break;
            case "stop":
                stopVpn();  // 停止VPN连接
                break;
        }
        return START_STICKY;
    }

    /**
     * 停止VPN连接并释放资源
     */
    private synchronized void stopVpn() {
        try {
            if (descriptor != null) {
                descriptor.close(); // 关闭VPN隧道接口
            }

            if (thread != null) {
                thread.interrupt();
            }
        } catch (IOException ignored) {
            // 关闭时的IO异常通常可以忽略
        } finally {
            descriptor = null; // 释放引用
            sendStatusUpdate("stop"); // 通知UI已停止
            stopSelf(); // 停止服务自身
        }
    }

    /**
     * 建立VPN连接
     */
    private synchronized void setupVpn() {
        // 如果已经建立连接则直接返回
        if (descriptor != null) return;

        try {
            // 使用Builder模式配置VPN参数
            descriptor = new Builder()
                    .addAddress("10.0.0.2", 32)       // 设置虚拟IP地址
                    .addRoute("0.0.0.0", 0)            // 拦截所有IPv4流量
                    .addDnsServer("114.114.114.114")    // 设置DNS服务器
                    .addAllowedApplication(getPackageName()) // 允许本应用通过VPN
//                    .addAllowedApplication("com.android.chrome")
                    .addAllowedApplication("com.android.browser") // 允许浏览器通过VPN
                    .setConfigureIntent(pendingIntent)
                    .establish(); // 建立VPN连接

            sendStatusUpdate("start"); // 通知UI已连接
        } catch (Exception e) {
            throw new RuntimeException("VPN setup failed", e);
        }

        //解析数据包
        BytesParse bytesParse = new BytesParse(this);
        thread = new Thread(bytesParse);
        thread.start();
    }

    /**
     * 发送状态更新广播
     *
     * @param status 当前状态("start"或"stop")
     */
    private void sendStatusUpdate(String status) {
        LocalBroadcastManager.getInstance(this)
                .sendBroadcast(new Intent("com.example.UPDATE_TEXT")
                        .putExtra("status", status));
    }
}