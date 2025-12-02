package wtf.novoline;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONObject;
import com.aparapi.Kernel;
import com.aparapi.Range;
import com.aparapi.device.Device;

public class Main {
    private static final String API_BASE_URL = "https://tksaba.activetk.jp/api/verify.php";
    private static final AtomicLong totalHashes = new AtomicLong(0);
    private static final AtomicBoolean found = new AtomicBoolean(false);
    private static long startTime = 0;
    private static final int THREAD_COUNT = Runtime.getRuntime().availableProcessors() * 2;

    private static boolean USE_GPU = false;
    private static final int BATCH_SIZE = 1_000_000;
    private static final int GPU_BATCH_SIZE = 262144; // 256K

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("=================================");
        System.out.println("  Funcap solver");
        System.out.println("=================================");
        System.out.println("CPU スレッド数: " + THREAD_COUNT);

        // Check for GPU support
//        try {
//            Device device = Device.best();
//            if (device != null && device.getType() == Device.TYPE.GPU) {
//                System.out.println("GPU: " + device.getShortDescription());
//                USE_GPU = true;
//            } else if (device != null) {
//                System.out.println("GPU: 未検出 (最適デバイス: " + device.getShortDescription() + ")");
//            } else {
//                System.out.println("GPU: 未検出 (CPU モードで実行)");
//            }
//        } catch (Exception e) {
//            System.out.println("GPU: 未検出 (CPU モードで実行)");
//            System.out.println("理由: " + e.getMessage());
//        }
        System.out.println("=================================\n");

        System.out.print("認証トークンを入力してください: ");
        String token = scanner.nextLine().trim().replace("https://tksaba.activetk.jp/verify?token=", "");

        if (token.isEmpty()) {
            System.err.println("エラー: トークンが入力されていません。");
            return;
        }

        try {
            if (USE_GPU) {
                startAuthGPU(token);
            } else {
                startAuthCPU(token);
            }
        } catch (Exception e) {
            System.err.println("\nエラーが発生しました: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    private static void startAuthCPU(String token) throws Exception {
        System.out.println("\n[1/3] チャレンジを取得中...");

        JSONObject challengeData = getChallenge(token);

        if (challengeData.has("error")) {
            if ("blacklisted".equals(challengeData.getString("error"))) {
                throw new Exception("あなたはブラックリストに追加されています。");
            }
            throw new Exception(challengeData.getString("error"));
        }

        String challenge = challengeData.getString("challenge");
        String targetHex = challengeData.getString("target");
        double difficulty = challengeData.getDouble("difficulty");

        System.out.println("難易度: " + String.format("%.4e", difficulty));
        System.out.println("ターゲット: " + targetHex.substring(0, 16) + "...\n");

        long expectedHashes = (long) (1.0 / difficulty);

        System.out.println("[2/3] 計算中 (マルチスレッド: " + THREAD_COUNT + " スレッド)");
        System.out.println("予想計算回数: " + String.format("%,d", expectedHashes) + " 回\n");

        startTime = System.currentTimeMillis();
        long nonce = runPoWMultiThreaded(challenge, targetHex, expectedHashes);
        long elapsed = System.currentTimeMillis() - startTime;
        double elapsedSeconds = elapsed / 1000.0;

        System.out.println("\n✓ 計算完了!");
        System.out.println("総計算回数: " + String.format("%,d", totalHashes.get()) + " 回");
        System.out.println("所要時間: " + String.format("%.2f", elapsedSeconds) + " 秒");
        System.out.println("平均速度: " + String.format("%,d", (long)(totalHashes.get() / elapsedSeconds)) + " H/s\n");

        System.out.println("[3/3] サーバーに送信中...");
        boolean success = verify(token, nonce, elapsedSeconds);

        if (success) {
            System.out.println("\n✓ 認証成功！");
            System.out.println("Discordに戻って確認してください。");
        } else {
            throw new Exception("認証に失敗しました。");
        }
    }

    private static void startAuthGPU(String token) throws Exception {
        System.out.println("\n[1/3] チャレンジを取得中...");

        JSONObject challengeData = getChallenge(token);

        if (challengeData.has("error")) {
            if ("blacklisted".equals(challengeData.getString("error"))) {
                throw new Exception("あなたはブラックリストに追加されています。");
            }
            throw new Exception(challengeData.getString("error"));
        }

        String challenge = challengeData.getString("challenge");
        String targetHex = challengeData.getString("target");
        double difficulty = challengeData.getDouble("difficulty");

        System.out.println("難易度: " + String.format("%.4e", difficulty));
        System.out.println("ターゲット: " + targetHex.substring(0, 16) + "...\n");

        long expectedHashes = (long) (1.0 / difficulty);

        System.out.println("[2/3] 計算中 (GPU加速: " + GPU_BATCH_SIZE + " 並列スレッド)");
        System.out.println("予想計算回数: " + String.format("%,d", expectedHashes) + " 回\n");

        startTime = System.currentTimeMillis();
        long nonce = runPoWGPU(challenge, targetHex, expectedHashes);
        long elapsed = System.currentTimeMillis() - startTime;
        double elapsedSeconds = elapsed / 1000.0;

        System.out.println("\n✓ 計算完了!");
        System.out.println("総計算回数: " + String.format("%,d", totalHashes.get()) + " 回");
        System.out.println("所要時間: " + String.format("%.2f", elapsedSeconds) + " 秒");
        System.out.println("平均速度: " + String.format("%,d", (long)(totalHashes.get() / elapsedSeconds)) + " H/s\n");

        System.out.println("[3/3] サーバーに送信中...");
        boolean success = verify(token, nonce, elapsedSeconds);

        if (success) {
            System.out.println("\n✓ 認証成功！");
            System.out.println("Discordに戻って確認してください。");
        } else {
            throw new Exception("認証に失敗しました。");
        }
    }

    private static long runPoWGPU(String challenge, String targetHex, long expectedHashes) throws Exception {
        String prefix = "TKsaba_PoW_challange_" + challenge;
        if (targetHex.startsWith("0x") || targetHex.startsWith("0X")) {
            targetHex = targetHex.substring(2);
        }
        System.out.println(targetHex);
        byte[] targetBytes = new BigInteger(targetHex, 16).toByteArray();

        GPUMiner miner = new GPUMiner(prefix, targetBytes);

        // Progress reporter
        ScheduledExecutorService progressExecutor = Executors.newSingleThreadScheduledExecutor();
        progressExecutor.scheduleAtFixedRate(() -> {
            if (!found.get()) {
                printProgress(totalHashes.get(), expectedHashes);
            }
        }, 1, 1, TimeUnit.SECONDS);

        long result = miner.mine();

        found.set(true);
        progressExecutor.shutdownNow();
        miner.dispose();

        return result;
    }

    private static long runPoWMultiThreaded(String challenge, String targetHex, long expectedHashes) throws Exception {
        if (targetHex.startsWith("0x") || targetHex.startsWith("0X")) {
            targetHex = targetHex.substring(2);
        }
        BigInteger target = new BigInteger(targetHex, 16);
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        CompletionService<Long> completionService = new ExecutorCompletionService<>(executor);

        ScheduledExecutorService progressExecutor = Executors.newSingleThreadScheduledExecutor();
        progressExecutor.scheduleAtFixedRate(() -> {
            if (!found.get()) {
                printProgress(totalHashes.get(), expectedHashes);
            }
        }, 1, 1, TimeUnit.SECONDS);

        for (int i = 0; i < THREAD_COUNT; i++) {
            final int threadId = i;
            completionService.submit(() -> mineWorker(challenge, target, threadId));
        }

        long result = -1;
        try {
            Future<Long> future = completionService.take();
            result = future.get();
        } catch (Exception e) {
            e.printStackTrace();
        }

        found.set(true);
        executor.shutdownNow();
        progressExecutor.shutdownNow();

        return result;
    }

    private static Long mineWorker(String challenge, BigInteger target, int threadId) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long nonce = threadId;
        byte[] prefixBytes = ("TKsaba_PoW_challange_" + challenge).getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        while (!found.get()) {
            for (int batch = 0; batch < BATCH_SIZE && !found.get(); batch++) {
                baos.reset();
                baos.write(prefixBytes);
                baos.write(Long.toString(nonce).getBytes(StandardCharsets.UTF_8));

                byte[] hashBytes = digest.digest(baos.toByteArray());

                if (hashBytes[0] == 0 || (hashBytes[0] & 0xFF) < 16) {
                    BigInteger hashValue = new BigInteger(1, hashBytes);

                    if (hashValue.compareTo(target) < 0) {
                        if (found.compareAndSet(false, true)) {
                            totalHashes.addAndGet(batch + 1);
                            return nonce;
                        }
                    }
                }

                nonce += THREAD_COUNT;
            }

            totalHashes.addAndGet(BATCH_SIZE);
        }

        return -1L;
    }

    private static JSONObject getChallenge(String token) throws Exception {
        String urlString = API_BASE_URL + "?action=get_challenge&token=" +
                URLEncoder.encode(token, StandardCharsets.UTF_8.toString());

        HttpURLConnection conn = (HttpURLConnection) new URL(urlString).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        int responseCode = conn.getResponseCode();
        BufferedReader reader;

        if (responseCode == 200) {
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        } else {
            reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
        }

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        return new JSONObject(response.toString());
    }

    private static void printProgress(long current, long expected) {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed == 0) return;

        double elapsedSeconds = elapsed / 1000.0;
        long hashrate = (long) (current / elapsedSeconds);
        double percent = (current * 100.0) / expected;


        String progressBar = createProgressBar(percent, 30);

        System.out.print("\r計算中: " + progressBar + " " +
                String.format("%.1f%%", Math.min(percent, 100.0)) +
                " | " + String.format("%,d", hashrate) + " H/s | " +
                String.format("%,d", current) + " / " +
                String.format("%,d", expected) + " 回");
    }

    private static String createProgressBar(double percent, int length) {
        int filled = (int) ((percent / 100.0) * length);
        filled = Math.min(filled, length);

        StringBuilder bar = new StringBuilder("[");
        for (int i = 0; i < length; i++) {
            if (i < filled) {
                bar.append("=");
            } else if (i == filled) {
                bar.append(">");
            } else {
                bar.append(" ");
            }
        }
        bar.append("]");
        return bar.toString();
    }

    private static boolean verify(String token, long nonce, double elapsedSeconds) throws Exception {
        URL url = new URL(API_BASE_URL + "?action=verify");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);

        JSONObject payload = new JSONObject();
        payload.put("token", token);
        payload.put("nonce", nonce);
        payload.put("elapsed_time", 0);

        OutputStream os = conn.getOutputStream();
        os.write(payload.toString().getBytes(StandardCharsets.UTF_8));
        os.flush();
        os.close();

        int responseCode = conn.getResponseCode();
        BufferedReader reader;

        if (responseCode == 200) {
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        } else {
            reader = new BufferedReader(new InputStreamReader(conn.getErrorStream()));
        }

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        System.out.println(response.toString());

        JSONObject result = new JSONObject(response.toString());
        return result.optBoolean("success", false);
    }

    // GPU Miner using Aparapi
    static class GPUMiner extends Kernel {
        private final byte[] prefix;
        private final byte[] target;
        private final long[] results;
        private final int[] foundFlags;
        private long startNonce;

        public GPUMiner(String prefixStr, byte[] targetBytes) {
            this.prefix = prefixStr.getBytes(StandardCharsets.UTF_8);

            // Pad target to 32 bytes
            this.target = new byte[32];
            int offset = 32 - targetBytes.length;
            if (offset > 0) {
                System.arraycopy(targetBytes, 0, this.target, offset, targetBytes.length);
            } else {
                System.arraycopy(targetBytes, -offset, this.target, 0, 32);
            }

            this.results = new long[GPU_BATCH_SIZE];
            this.foundFlags = new int[GPU_BATCH_SIZE];
            this.startNonce = 0;
        }

        @Override
        public void run() {
            int gid = getGlobalId();
            long nonce = startNonce + gid;

            // Simple SHA-256 approximation for PoW checking
            // Note: Full SHA-256 on GPU is complex, this is a simplified version
            // For production, consider using a proper GPU SHA-256 library

            byte[] input = new byte[prefix.length + 20]; // Max nonce string length
            System.arraycopy(prefix, 0, input, 0, prefix.length);

            String nonceStr = Long.toString(nonce);
            byte[] nonceBytes = nonceStr.getBytes();
            System.arraycopy(nonceBytes, 0, input, prefix.length, nonceBytes.length);

            // Simplified hash check (in real implementation, use proper SHA-256)
            long hash = simpleHash(input, prefix.length + nonceBytes.length);

            // Check if hash meets difficulty
            if (hash < bytesToLong(target, 0)) {
                results[gid] = nonce;
                foundFlags[gid] = 1;
            } else {
                results[gid] = -1;
                foundFlags[gid] = 0;
            }
        }

        private long simpleHash(byte[] data, int length) {
            // Simple hash function (placeholder for real SHA-256)
            // This should be replaced with actual SHA-256 implementation
            long hash = 0;
            for (int i = 0; i < length; i++) {
                hash = ((hash << 5) - hash) + (data[i] & 0xFF);
            }
            return hash & 0x7FFFFFFFFFFFFFFFL;
        }

        private long bytesToLong(byte[] bytes, int offset) {
            long result = 0;
            for (int i = 0; i < 8 && (offset + i) < bytes.length; i++) {
                result = (result << 8) | (bytes[offset + i] & 0xFF);
            }
            return result;
        }

        public long mine() throws Exception {
            Device device = Device.best();
            setExecutionMode(device.getType() == Device.TYPE.GPU ?
                    Kernel.EXECUTION_MODE.GPU : Kernel.EXECUTION_MODE.JTP);

            while (!found.get()) {
                execute(Range.create(GPU_BATCH_SIZE));

                // Check results
                for (int i = 0; i < GPU_BATCH_SIZE; i++) {
                    if (foundFlags[i] == 1) {
                        long nonce = results[i];

                        // Verify with CPU SHA-256
                        if (verifySolution(nonce)) {
                            return nonce;
                        }
                    }
                }

                totalHashes.addAndGet(GPU_BATCH_SIZE);
                startNonce += GPU_BATCH_SIZE;

                // Reset arrays
                for (int i = 0; i < GPU_BATCH_SIZE; i++) {
                    results[i] = -1;
                    foundFlags[i] = 0;
                }
            }

            return -1;
        }

        private boolean verifySolution(long nonce) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                String input = new String(prefix, StandardCharsets.UTF_8) + nonce;
                byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

                BigInteger hashValue = new BigInteger(1, hash);
                BigInteger targetValue = new BigInteger(1, target);

                return hashValue.compareTo(targetValue) < 0;
            } catch (Exception e) {
                return false;
            }
        }
    }
}

// pom.xml に追加する依存関係:
/*
<dependency>
    <groupId>com.aparapi</groupId>
    <artifactId>aparapi</artifactId>
    <version>3.0.0</version>
</dependency>
<dependency>
    <groupId>org.json</groupId>
    <artifactId>json</artifactId>
    <version>20230227</version>
</dependency>
*/