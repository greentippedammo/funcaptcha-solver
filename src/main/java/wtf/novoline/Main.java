package wtf.novoline;

import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
    private static final AtomicLong nonceResult = new AtomicLong(0);
    private static long startTime = 0;

    // Tune these:
    private static final int GPU_BATCH_SIZE = 1_048_576; // 1M work items (large to keep GPU busy)
    private static final int GPU_LOCAL_SIZE = 256;       // local work group size (multiple of 32/64)
    private static final int THREAD_COUNT = Runtime.getRuntime().availableProcessors() * 2;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("=================================");
        System.out.println("  Funcap solver (GPU SHA-256)");
        System.out.println("=================================");
        System.out.println("CPU スレッド数: " + THREAD_COUNT);

        try {
            Device device = Device.best();
            if (device != null && device.getType() == Device.TYPE.GPU) {
                System.out.println("GPU: " + device.getShortDescription());
            } else if (device != null) {
                System.out.println("GPU: 未検出 (最適デバイス: " + device.getShortDescription() + ")");
            } else {
                System.out.println("GPU: 未検出 (CPU モードで実行)");
            }
        } catch (Exception e) {
            System.out.println("GPU: 未検出 (CPU モードで実行)");
            System.out.println("理由: " + e.getMessage());
        }
        System.out.println("=================================\n");

        System.out.print("認証トークンを入力してください: ");
        String token = scanner.nextLine().trim().replace("https://tksaba.activetk.jp/verify?token=", "");

        if (token.isEmpty()) {
            System.err.println("エラー: トークンが入力されていません。");
            return;
        }

        try {
            startAuthGPU(token);
        } catch (Exception e) {
            System.err.println("\nエラーが発生しました: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
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

        System.out.println("[2/3] 計算中 (GPU SHA-256: batch " + String.format("%,d", GPU_BATCH_SIZE) + ")");
        System.out.println("予想計算回数: " + String.format("%,d", expectedHashes) + " 回\n");

        startTime = System.currentTimeMillis();
        long nonce = SHA256PoWGPU.solve(challenge, targetHex, 1 / difficulty);
        long elapsed = System.currentTimeMillis() - startTime;
        double elapsedSeconds = elapsed / 1000.0;

        System.out.println("\n✓ 計算完了!");
        System.out.println("総計算回数: " + String.format("%,d", totalHashes.get()) + " 回");
        System.out.println("所要時間: " + String.format("%d", elapsed) + " ms");
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
        // assume single-block messages (prefix + decimal nonce <= 55 bytes).
        String prefixStr = "TKsaba_PoW_challange_" + challenge;
        byte[] prefixBytes = prefixStr.getBytes(StandardCharsets.UTF_8);
        if (prefixBytes.length + 11 > 56) {
            // safety: if prefix+max-decimal-nonce likely exceed single-block,
            // fall back to CPU worker (avoid wrong GPU kernel behavior).
            System.out.println("Prefix + nonce may exceed single-block SHA-256 limit. Falling back to CPU miner.");
            return runPoWMultiThreaded(challenge, targetHex, expectedHashes);
        }

        if (targetHex.startsWith("0x") || targetHex.startsWith("0X")) {
            targetHex = targetHex.substring(2);
        }

        // convert target hex to 32 bytes
        byte[] targetBytes = new BigInteger(targetHex, 16).toByteArray();
        byte[] target32 = new byte[32];
        int offset = 32 - targetBytes.length;
        if (offset > 0) {
            System.arraycopy(targetBytes, 0, target32, offset, targetBytes.length);
        } else {
            System.arraycopy(targetBytes, -offset, target32, 0, 32);
        }

        // convert target32 to int[8] big-endian words
        int[] targetWords = new int[8];
        for (int i = 0; i < 8; i++) {
            int idx = i * 4;
            int w = ((target32[idx] & 0xFF) << 24) | ((target32[idx + 1] & 0xFF) << 16) |
                    ((target32[idx + 2] & 0xFF) << 8) | (target32[idx + 3] & 0xFF);
            targetWords[i] = w;
        }

        // Create GPU miner with prefix bytes and target
        GPUSha256Miner miner = new GPUSha256Miner(prefixBytes, prefixBytes.length, targetWords);

        // progress reporter
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

    // The original CPU multi-threaded fallback (unchanged except minor)
    public static long runPoWMultiThreaded(String challenge, String targetHex, long expectedHashes) throws Exception {
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

        result = nonceResult.get();
        found.set(true);
        executor.shutdownNow();
        progressExecutor.shutdownNow();

        return result;
    }

    private static Long mineWorker(String challenge, BigInteger target, int threadId) throws Exception {
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        long nonce = threadId;
        byte[] prefixBytes = ("TKsaba_PoW_challange_" + challenge).getBytes(StandardCharsets.UTF_8);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        while (!found.get()) {
            for (int batch = 0; batch < 1_000_000 && !found.get(); batch++) {
                baos.reset();
                baos.write(prefixBytes);
                baos.write(Long.toString(nonce).getBytes(StandardCharsets.UTF_8));

                byte[] hashBytes = digest.digest(baos.toByteArray());

                if (hashBytes[0] == 0 || (hashBytes[0] & 0xFF) < 16) {
                    BigInteger hashValue = new BigInteger(1, hashBytes);

                    if (hashValue.compareTo(target) < 0) {
                        if (found.compareAndSet(false, true)) {
                            totalHashes.addAndGet(batch + 1);
                            nonceResult.set(nonce);
                            return nonce;
                        }
                    }
                }

                nonce += THREAD_COUNT;
            }

            totalHashes.addAndGet(1_000_000);
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

    // ---------- Aparapi GPU miner (single-block SHA-256, no allocations in run()) ----------
    static class GPUSha256Miner extends Kernel {
        // Inputs
        private final byte[] prefix; // prefix bytes
        private final int prefixLen;
        private final int[] targetWords; // 8 words (big-endian)

        // Output arrays (per work-item)
        private final int[] foundFlags; // 1 if candidate found
        private final int[] resultsLow; // store nonce (as int)

        // temp buffers reused by kernel (must be fields, not created in run())
        private final int[] buf; // message bytes as 0..255 (single-block 64 bytes)
        private final int[] w;   // message schedule (64)
        private final int[] digs; // digits for nonce conversion

        // SHA-256 K constants (final)
        private final int[] K = new int[]{
                0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
                0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
                0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
                0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
                0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
                0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
                0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
        };

        // host-managed base nonce (int)
        private int baseNonce;

        public GPUSha256Miner(byte[] prefixBytes, int prefixLen, int[] targetWords) {
            this.prefix = new byte[prefixLen];
            for (int i = 0; i < prefixLen; i++) this.prefix[i] = prefixBytes[i];
            this.prefixLen = prefixLen;

            this.targetWords = new int[8];
            for (int i = 0; i < 8; i++) this.targetWords[i] = targetWords[i];

            // arrays sized to GPU_BATCH_SIZE — Aparapi requires these be primitive arrays
            this.foundFlags = new int[GPU_BATCH_SIZE];
            this.resultsLow = new int[GPU_BATCH_SIZE];

            this.buf = new int[64]; // single block 64 bytes
            this.w = new int[64];
            this.digs = new int[12]; // up to 10-11 decimal digits for 32-bit nonce

            this.baseNonce = 0;
        }

        // Host sets baseNonce before execute
        public void setBaseNonce(int base) {
            this.baseNonce = base;
        }

        @Override
        public void run() {
            int gid = getGlobalId();
            int nonce = baseNonce + gid; // 32-bit nonce in-kernel (no long)

            // Build message bytes in buf[] (prefix + decimal(nonce))
            int idx = 0;
            for (int i = 0; i < prefixLen; i++) {
                buf[idx++] = prefix[i] & 0xFF;
            }

            // convert nonce to decimal ASCII into digs[] (reverse), then copy reversed
            int t = nonce;
            int digCount = 0;
            if (t == 0) {
                digs[digCount++] = '0';
            } else {
                while (t != 0 && digCount < 11) {
                    int d = (t % 10);
                    digs[digCount++] = 48 + d;
                    t = t / 10;
                }
                // reverse into buf
                for (int j = digCount - 1; j >= 0; j--) {
                    buf[idx++] = digs[j];
                }
            }

            int msgLen = idx;
            // Single-block padding: set w[0..15]
            for (int i = 0; i < 16; i++) w[i] = 0;
            int bytePos = 0;
            for (int i = 0; i < 16; i++) {
                int word = 0;
                for (int b = 0; b < 4; b++) {
                    word = (word << 8);
                    if (bytePos < msgLen) {
                        word |= (buf[bytePos] & 0xFF);
                        bytePos++;
                    }
                }
                w[i] = word;
            }
            // append 0x80 at message end (big-endian in word)
            int rem = msgLen % 4;
            if (rem == 0) {
                int posWord = msgLen / 4;
                if (posWord < 16) w[posWord] = (0x80 << 24);
            } else {
                int posWord = msgLen / 4;
                int shift = (3 - (msgLen % 4)) * 8;
                w[posWord] |= (0x80 << shift);
            }
            // set length in bits in w[15] (we assume length < 2^32 bits)
            int totalBits = msgLen * 8;
            w[15] = totalBits;

            // expand
            for (int t2 = 16; t2 < 64; t2++) {
                int s0 = ((w[t2 - 15] >>> 7) | (w[t2 - 15] << 25)) ^ ((w[t2 - 15] >>> 18) | (w[t2 - 15] << 14)) ^ (w[t2 - 15] >>> 3);
                int s1 = ((w[t2 - 2] >>> 17) | (w[t2 - 2] << 15)) ^ ((w[t2 - 2] >>> 19) | (w[t2 - 2] << 13)) ^ (w[t2 - 2] >>> 10);
                w[t2] = w[t2 - 16] + s0 + w[t2 - 7] + s1;
            }

            // initial hash values
            int a = 0x6a09e667;
            int b = 0xbb67ae85;
            int c = 0x3c6ef372;
            int d = 0xa54ff53a;
            int e = 0x510e527f;
            int f = 0x9b05688c;
            int g = 0x1f83d9ab;
            int h = 0x5be0cd19;

            for (int t2 = 0; t2 < 64; t2++) {
                int S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
                int ch = (e & f) ^ ((~e) & g);
                int temp1 = h + S1 + ch + K[t2] + w[t2];
                int S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
                int maj = (a & b) ^ (a & c) ^ (b & c);
                int temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            int H0 = 0x6a09e667 + a;
            int H1 = 0xbb67ae85 + b;
            int H2 = 0x3c6ef372 + c;
            int H3 = 0xa54ff53a + d;
            int H4 = 0x510e527f + e;
            int H5 = 0x9b05688c + f;
            int H6 = 0x1f83d9ab + g;
            int H7 = 0x5be0cd19 + h;

            // lexicographic compare against targetWords
            boolean meets = false;
            if (H0 < targetWords[0]) meets = true;
            else if (H0 == targetWords[0]) {
                if (H1 < targetWords[1]) meets = true;
                else if (H1 == targetWords[1]) {
                    if (H2 < targetWords[2]) meets = true;
                    else if (H2 == targetWords[2]) {
                        if (H3 < targetWords[3]) meets = true;
                        else if (H3 == targetWords[3]) {
                            if (H4 < targetWords[4]) meets = true;
                            else if (H4 == targetWords[4]) {
                                if (H5 < targetWords[5]) meets = true;
                                else if (H5 == targetWords[5]) {
                                    if (H6 < targetWords[6]) meets = true;
                                    else if (H6 == targetWords[6]) {
                                        if (H7 < targetWords[7]) meets = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (meets) {
                foundFlags[gid] = 1;
                resultsLow[gid] = nonce;
            } else {
                foundFlags[gid] = 0;
                resultsLow[gid] = 0;
            }
        }

        public long mine() throws Exception {
            Device device = Device.best();
            if (device != null && device.getType() == Device.TYPE.GPU) {
                setExecutionMode(Kernel.EXECUTION_MODE.GPU);
            } else {
                setExecutionMode(Kernel.EXECUTION_MODE.JTP);
            }

            int base = 0;
            while (!found.get()) {
                // set base and execute
                setBaseNonce(base);
                // Clear flags for safety (host-side arrays are visible to kernel)
                for (int i = 0; i < GPU_BATCH_SIZE; i++) {
                    foundFlags[i] = 0;
                    resultsLow[i] = 0;
                }

                // execute with specified local size
                execute(Range.create(GPU_BATCH_SIZE, GPU_LOCAL_SIZE));

                // scan results
                for (int i = 0; i < GPU_BATCH_SIZE; i++) {
                    if (foundFlags[i] == 1) {
                        int nonce = resultsLow[i];
                        // verify on CPU
                        if (verifySolution((long)nonce)) {
                            return nonce & 0xFFFFFFFFL;
                        }
                    }
                }

                totalHashes.addAndGet(GPU_BATCH_SIZE);
                base += GPU_BATCH_SIZE;
            }

            return -1L;
        }

        private boolean verifySolution(long nonce) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                String input = new String(prefix, 0, prefixLen, StandardCharsets.UTF_8) + (nonce & 0xFFFFFFFFL);
                byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

                BigInteger hashValue = new BigInteger(1, hash);
                // reconstruct target as BigInteger
                byte[] t = new byte[32];
                for (int i = 0; i < 8; i++) {
                    int w = targetWords[i];
                    int idx = i * 4;
                    t[idx] = (byte)((w >>> 24) & 0xFF);
                    t[idx+1] = (byte)((w >>> 16) & 0xFF);
                    t[idx+2] = (byte)((w >>> 8) & 0xFF);
                    t[idx+3] = (byte)(w & 0xFF);
                }
                BigInteger target = new BigInteger(1, t);
                return hashValue.compareTo(target) < 0;
            } catch (Exception e) {
                return false;
            }
        }

        public void dispose() {
            // no op
        }
    }
}
