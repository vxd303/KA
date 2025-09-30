package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason) {
    private static final String TAG = "RevocationList";
    private static final String STATUS_FILE = "revocation_status.json";
    private static final String PREFS_NAME = "revocation_list";
    private static final String KEY_LAST_UPDATE = "last_update";
    private static final String KEY_PUBLISH_TIME = "publish_time";

    private static JSONObject data = null;
    private static long lastUpdate = 0;
    private static String publishTime = null;

    private static String toString(InputStream input) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } else {
            var output = new ByteArrayOutputStream(8192);
            var buffer = new byte[8192];
            for (int length; (length = input.read(buffer)) != -1; ) {
                output.write(buffer, 0, length);
            }
            return output.toString();
        }
    }

    private static JSONObject parseStatus(InputStream inputStream) throws IOException {
        try {
            var statusListJson = new JSONObject(toString(inputStream));
            // 尝试获取发布时间
            if (statusListJson.has("publishTime")) {
                publishTime = statusListJson.getString("publishTime");
            }
            return statusListJson.getJSONObject("entries");
        } catch (JSONException e) {
            throw new IOException(e);
        }
    }

    private static synchronized JSONObject getStatus() {
        if (data != null) {
            return data;
        }

        var context = AppApplication.app;
        var prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        lastUpdate = prefs.getLong(KEY_LAST_UPDATE, 0);
        publishTime = prefs.getString(KEY_PUBLISH_TIME, null);

        // 先尝试加载本地缓存的文件
        File statusFile = new File(context.getFilesDir(), STATUS_FILE);
        if (statusFile.exists()) {
            try (var input = new FileInputStream(statusFile)) {
                data = parseStatus(input);
                return data;
            } catch (IOException e) {
                Log.w(TAG, "Failed to load cached status file", e);
            }
        }

        // 加载内置的状态文件作为后备
        var res = context.getResources();
        try (var input = res.openRawResource(R.raw.status)) {
            data = parseStatus(input);
            return data;
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse certificate revocation status", e);
        }
    }

    /**
     * 从网络更新吊销列表
     * @return 是否更新成功
     */
    public static boolean updateFromNetwork() {
        var statusUrl = "https://android.googleapis.com/attestation/status";
        var resName = "android:string/vendor_required_attestation_revocation_list_url";
        var context = AppApplication.app;
        var res = context.getResources();

        // 检查是否有自定义的URL
        // noinspection DiscouragedApi
        var id = res.getIdentifier(resName, null, null);
        if (id != 0) {
            var url = res.getString(id);
            if (!statusUrl.equals(url) && url.toLowerCase(Locale.ROOT).startsWith("https")) {
                statusUrl = url;
            }
        }

        HttpURLConnection connection = null;
        try {
            URL url = new URL(statusUrl);
            connection = (HttpURLConnection) url.openConnection();
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // 从 HTTP 响应头获取 Last-Modified 时间
                String lastModifiedHeader = connection.getHeaderField("Last-Modified");
                long serverLastModified = 0;
                if (lastModifiedHeader != null) {
                    try {
                        serverLastModified = connection.getHeaderFieldDate("Last-Modified", 0);
                    } catch (Exception e) {
                        Log.w(TAG, "Failed to parse Last-Modified header", e);
                    }
                }

                // 下载并保存到本地
                File statusFile = new File(context.getFilesDir(), STATUS_FILE);
                try (var input = connection.getInputStream();
                     var output = new FileOutputStream(statusFile)) {
                    byte[] buffer = new byte[8192];
                    int length;
                    while ((length = input.read(buffer)) != -1) {
                        output.write(buffer, 0, length);
                    }
                }

                // 重新加载数据
                try (var input = new FileInputStream(statusFile)) {
                    data = parseStatus(input);
                }

                // 如果从响应头获取到了服务器的最后修改时间，优先使用它
                // 否则使用当前时间作为更新时间
                var prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                if (serverLastModified > 0) {
                    lastUpdate = serverLastModified;
                } else {
                    lastUpdate = System.currentTimeMillis();
                }

                prefs.edit()
                    .putLong(KEY_LAST_UPDATE, lastUpdate)
                    .putString(KEY_PUBLISH_TIME, publishTime)
                    .apply();

                Log.i(TAG, "Successfully updated revocation list from network. Last-Modified: " +
                    (serverLastModified > 0 ? new java.util.Date(serverLastModified) : "not available"));
                return true;
            } else {
                Log.w(TAG, "Failed to update revocation list: HTTP " + responseCode);
                return false;
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to update revocation list from network", e);
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * 获取上次更新时间
     * @return 时间戳(毫秒),如果从未更新则返回0
     */
    public static long getLastUpdateTime() {
        if (lastUpdate == 0) {
            var prefs = AppApplication.app.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            lastUpdate = prefs.getLong(KEY_LAST_UPDATE, 0);
        }
        return lastUpdate;
    }

    /**
     * 获取吊销列表发布时间
     * @return 发布时间字符串,如果未知则返回null
     */
    public static String getPublishTime() {
        if (publishTime == null && data == null) {
            getStatus(); // 确保数据已加载
        }
        return publishTime;
    }

    public static RevocationList get(BigInteger serialNumber) {
        // 确保数据已加载
        JSONObject statusData = getStatus();

        String serialNumberString = serialNumber.toString(16).toLowerCase();
        JSONObject revocationStatus;
        try {
            revocationStatus = statusData.getJSONObject(serialNumberString);
        } catch (JSONException e) {
            return null;
        }
        try {
            var status = revocationStatus.getString("status");
            var reason = revocationStatus.getString("reason");
            return new RevocationList(status, reason);
        } catch (JSONException e) {
            return new RevocationList("", "");
        }
    }

    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
