package com.example.vpnservice_learn;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.*;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * 主Activity，提供VPN控制界面和网络测试功能
 * 主要功能：
 * 1. VPN开关控制
 * 2. 网络请求测试
 * 3. 日志输出显示
 */
public class MainActivity extends AppCompatActivity {
    // 日志输出文本框
    private TextView outputText;
    // 下载速度
    private TextView speedText;
    // VPN权限请求的结果回调
    private ActivityResultLauncher<Intent> vpnLauncher;
    // VPN服务控制Intent
    private Intent vpnIntent;
    // 标识开关状态变化是否由程序触发（避免循环触发）
    private boolean isProgrammaticChange = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();            // 初始化界面组件
        setupVpnLauncher();     // 设置VPN权限请求回调
        setupBroadcastReceiver(); // 设置VPN状态广播接收
    }

    /**
     * 初始化界面视图和事件
     */
    private void initViews() {

        speedText = findViewById(R.id.speedText);

        outputText = findViewById(R.id.outputText);
        // 使用原生Switch组件（兼容性警告已忽略）
        @SuppressLint("UseSwitchCompatOrMaterialCode") Switch switchButton = findViewById(R.id.vpnSwitch);

        // VPN开关状态变化监听
        switchButton.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (!isProgrammaticChange) {  // 避免程序触发的状态变化重复处理
                handleVpnToggle(isChecked);
            }
        });

        // 网络测试按钮点击事件
        findViewById(R.id.visit).setOnClickListener(v ->
                http(((EditText)findViewById(R.id.editUrl)).getText().toString()));

        // 清空日志按钮点击事件
        findViewById(R.id.btnClear).setOnClickListener(v ->
                outputText.setText(""));
    }

    /**
     * 设置VPN权限请求回调
     * 处理用户是否授予VPN权限的结果
     */
    private void setupVpnLauncher() {
        vpnLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        startVpnService();  // 用户已授权，启动VPN服务
                    } else {
                        // 用户拒绝授权，重置开关状态
                        ((Switch)findViewById(R.id.vpnSwitch)).setChecked(false);
                        appendOutput("VPN权限被拒绝");
                    }
                });
    }

    /**
     * 设置VPN状态广播接收器
     * 接收来自VPN服务的状态更新
     */
    private void setupBroadcastReceiver() {
        LocalBroadcastManager.getInstance(this).registerReceiver(
                new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        String status = intent.getStringExtra("status");
                        String speed= intent.getStringExtra("speed");
                        if (status != null) {
                            // 更新开关状态以反映VPN实际状态
                            @SuppressLint("UseSwitchCompatOrMaterialCode") Switch switchBtn = findViewById(R.id.vpnSwitch);
                            boolean isRunning = "start".equals(status);

                            isProgrammaticChange = true;  // 标记为程序触发的状态变化
                            switchBtn.setChecked(isRunning);
                            isProgrammaticChange = false;

                            appendOutput(isRunning ? "启动Vpn" : "关闭Vpn");
                        }

                        if(speed!=null){
                            speedText.setText("下载速度："+speed);
                        }
                    }
                },
                new IntentFilter("com.example.UPDATE_TEXT")  // 监听自定义广播
        );
    }

    /**
     * 处理VPN开关状态变化
     * @param isChecked 开关是否开启
     */
    private void handleVpnToggle(boolean isChecked) {
        if (isChecked) {
            // 检查是否需要请求VPN权限
            Intent intent = VpnService.prepare(this);
            if (intent != null) {
                vpnLauncher.launch(intent);  // 需要权限，发起请求
            } else {
                startVpnService();  // 已有权限，直接启动
            }
        } else {
            stopVpnService();  // 关闭VPN
        }
    }

    /**
     * 启动VPN服务
     */
    private void startVpnService() {
        vpnIntent = new Intent(this, MyVpnService.class)
                .putExtra("status", "start");  // 设置启动状态
        startService(vpnIntent);
    }

    /**
     * 停止VPN服务
     */
    private void stopVpnService() {
        if (vpnIntent != null) {
            startService(vpnIntent.putExtra("status", "stop"));  // 设置停止状态
        }
    }

    /**
     * 追加日志到输出框
     * @param text 要添加的日志文本
     */
    private void appendOutput(String text) {
        // 添加时间戳
        String time = new SimpleDateFormat("HH:mm:ss", Locale.getDefault())
                .format(new Date());
        // 格式化输出
        outputText.append(
                (outputText.length() > 0 ? "\n\n" : "") +  // 非第一条日志添加空行
                        String.format("[%s] %s", time, text)
        );
        // 自动滚动到底部
        findViewById(R.id.scrollView)
                .post(() -> ((ScrollView)findViewById(R.id.scrollView))
                        .fullScroll(View.FOCUS_DOWN));
    }

    /**
     * 发起HTTP GET请求
     * @param url 请求的URL地址
     */
    private void http(String url) {
        new Thread(() -> {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);  // 5秒连接超时

                int responseCode = conn.getResponseCode();
                if (responseCode == HttpURLConnection.HTTP_OK) {
                    try (InputStream is = conn.getInputStream()) {
                        String response = readStream(is);
                        runOnUiThread(() -> appendOutput(response));  // 在主线程更新UI
                    }
                } else {
                    runOnUiThread(() -> appendOutput("请求失败: " + responseCode));
                }
            } catch (IOException e) {
                runOnUiThread(() -> appendOutput("请求异常: " + e.getMessage()));
            } finally {
                if (conn != null) {
                    conn.disconnect();  // 确保连接关闭
                }
            }
        }).start();
    }

    /**
     * 从输入流读取字符串
     * @param is 输入流
     * @return 读取到的字符串
     * @throws IOException 读取异常
     */
    private String readStream(InputStream is) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);  // 逐行读取
            }
            return response.toString();
        }
    }
}