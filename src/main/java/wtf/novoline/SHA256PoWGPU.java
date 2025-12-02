package wtf.novoline;

import org.jocl.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.jocl.CL.*;

public class SHA256PoWGPU {

    private static cl_context context;
    private static cl_command_queue commandQueue;
    private static cl_program program;
    private static cl_kernel kernel;
    private static final AtomicBoolean found = new AtomicBoolean(false);

    public static long solve(String challenge, String targetHex, double expected) {
        byte[] prefixBytes = ("TKsaba_PoW_challange_" + challenge).getBytes(StandardCharsets.UTF_8);
        byte[] targetBytes = hexToBytes(targetHex.substring(2));

        initCL();

        long nonce = runPoWGPU(prefixBytes, targetBytes, (long) Math.pow(2, 18), expected);
        System.out.println("Found nonce: " + nonce);

        releaseCL();
        return nonce;
    }

    public static void main(String[] args) throws Exception {
        String challenge = "bc551d55e7ee55eca515b0a8ad13db2c";
        String targetHex = "0x0000000000000ea9f98ec05f26cab661aaa432733b9b1961d8855eb4ae52f1bf";

        byte[] prefixBytes = ("TKsaba_PoW_challange_" + challenge).getBytes(StandardCharsets.UTF_8);
        byte[] targetBytes = hexToBytes(targetHex.substring(2));

        initCL();

        long nonce = runPoWGPU(prefixBytes, targetBytes, 1024 * 256, 3);
        System.out.println("Found nonce: " + nonce);

        releaseCL();

        long l = Main.runPoWMultiThreaded(challenge, targetHex, 1);
        System.out.println("CPU:" + l);
    }

    private static void initCL() {
        CL.setExceptionsEnabled(true);

        // Get platform and device
        int[] numPlatformsArray = new int[1];
        clGetPlatformIDs(0, null, numPlatformsArray);
        cl_platform_id[] platforms = new cl_platform_id[numPlatformsArray[0]];
        clGetPlatformIDs(platforms.length, platforms, null);
        cl_platform_id platform = platforms[0];

        cl_device_id[] devices = new cl_device_id[1];
        clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 1, devices, null);
        cl_device_id device = devices[0];

        // Create context and queue
        cl_context_properties contextProperties = new cl_context_properties();
        contextProperties.addProperty(CL_CONTEXT_PLATFORM, platform);
        context = clCreateContext(contextProperties, 1, new cl_device_id[]{device}, null, null, null);
        commandQueue = clCreateCommandQueue(context, device, 0, null);

        // Load OpenCL program from sha256.cl
        String kernelSource = readKernelSource();
        program = clCreateProgramWithSource(context, 1, new String[]{kernelSource}, null, null);
        clBuildProgram(program, 0, null, null, null, null);
        kernel = clCreateKernel(program, "sha256Pow", null);
    }

    private static long runPoWGPU(byte[] prefix, byte[] target, long batchSize, double expected) {
        cl_mem prefixMem = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                Sizeof.cl_uchar * prefix.length, Pointer.to(prefix), null);
        cl_mem targetMem = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                Sizeof.cl_uchar * target.length, Pointer.to(target), null);
        cl_mem foundFlagMem = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                Sizeof.cl_int, Pointer.to(new int[]{0}), null);
        cl_mem resultNonceMem = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                Sizeof.cl_ulong, Pointer.to(new long[]{0}), null);

        long batchStart = 0;
        while (!found.get()) {
            clSetKernelArg(kernel, 0, Sizeof.cl_mem, Pointer.to(prefixMem));
            clSetKernelArg(kernel, 1, Sizeof.cl_int, Pointer.to(new int[]{prefix.length}));
            clSetKernelArg(kernel, 2, Sizeof.cl_mem, Pointer.to(targetMem));
            clSetKernelArg(kernel, 3, Sizeof.cl_ulong, Pointer.to(new long[]{batchStart}));
            clSetKernelArg(kernel, 4, Sizeof.cl_ulong, Pointer.to(new long[]{batchSize}));
            clSetKernelArg(kernel, 5, Sizeof.cl_mem, Pointer.to(foundFlagMem));
            clSetKernelArg(kernel, 6, Sizeof.cl_mem, Pointer.to(resultNonceMem));

            clEnqueueNDRangeKernel(commandQueue, kernel, 1, null,
                    new long[]{batchSize}, new long[]{256}, 0, null, null);
            clFinish(commandQueue);

            int[] foundFlag = new int[1];
            clEnqueueReadBuffer(commandQueue, foundFlagMem, CL_TRUE, 0, Sizeof.cl_int, Pointer.to(foundFlag), 0, null, null);
            if (foundFlag[0] != 0) {
                long[] resultNonce = new long[1];
                clEnqueueReadBuffer(commandQueue, resultNonceMem, CL_TRUE, 0, Sizeof.cl_ulong, Pointer.to(resultNonce), 0, null, null);
                found.set(true);
                return resultNonce[0];
            }

            batchStart += batchSize;
            System.out.print(String.format("\rHashes tried: %.2f", (batchStart / expected * 100)));
        }
        return -1;
    }

    private static void releaseCL() {
        if (kernel != null) clReleaseKernel(kernel);
        if (program != null) clReleaseProgram(program);
        if (commandQueue != null) clReleaseCommandQueue(commandQueue);
        if (context != null) clReleaseContext(context);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[(len + 1) / 2];
        int offset = (len % 2 == 1) ? 1 : 0;
        for (int i = 0; i < len / 2; i++) {
            data[i + offset] = (byte) ((Character.digit(hex.charAt(i * 2), 16) << 4)
                    + Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        if (offset == 1) data[0] = (byte) Character.digit(hex.charAt(0), 16);
        return data;
    }

    private static String readKernelSource() {
        return "/*\n" +
                " * sha256.cl - Fixed version with proper nonce encoding and SHA-256 implementation\n" +
                " */\n" +
                "\n" +
                "__constant uint k[] = {\n" +
                "   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,\n" +
                "   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,\n" +
                "   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,\n" +
                "   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,\n" +
                "   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,\n" +
                "   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,\n" +
                "   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,\n" +
                "   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };\n" +
                "\n" +
                "__constant uint h_init[] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };\n" +
                "\n" +
                "#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))\n" +
                "#define SHR(x, n) ((x) >> (n))\n" +
                "\n" +
                "#define S0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))\n" +
                "#define S1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))\n" +
                "#define S2(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))\n" +
                "#define S3(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))\n" +
                "\n" +
                "#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))\n" +
                "#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))\n" +
                "\n" +
                "void sha256_transform(uint state[8], const uchar data[64]) {\n" +
                "    uint w[64];\n" +
                "    uint a, b, c, d, e, f, g, h;\n" +
                "    \n" +
                "    // Prepare message schedule (big-endian)\n" +
                "    for (int i = 0; i < 16; i++) {\n" +
                "        w[i] = ((uint)data[i * 4] << 24) |\n" +
                "               ((uint)data[i * 4 + 1] << 16) |\n" +
                "               ((uint)data[i * 4 + 2] << 8) |\n" +
                "               ((uint)data[i * 4 + 3]);\n" +
                "    }\n" +
                "    \n" +
                "    for (int i = 16; i < 64; i++) {\n" +
                "        w[i] = S1(w[i - 2]) + w[i - 7] + S0(w[i - 15]) + w[i - 16];\n" +
                "    }\n" +
                "    \n" +
                "    // Initialize working variables\n" +
                "    a = state[0];\n" +
                "    b = state[1];\n" +
                "    c = state[2];\n" +
                "    d = state[3];\n" +
                "    e = state[4];\n" +
                "    f = state[5];\n" +
                "    g = state[6];\n" +
                "    h = state[7];\n" +
                "    \n" +
                "    // Compression function\n" +
                "    for (int i = 0; i < 64; i++) {\n" +
                "        uint t1 = h + S3(e) + CH(e, f, g) + k[i] + w[i];\n" +
                "        uint t2 = S2(a) + MAJ(a, b, c);\n" +
                "        h = g;\n" +
                "        g = f;\n" +
                "        f = e;\n" +
                "        e = d + t1;\n" +
                "        d = c;\n" +
                "        c = b;\n" +
                "        b = a;\n" +
                "        a = t1 + t2;\n" +
                "    }\n" +
                "    \n" +
                "    // Add compressed chunk to current hash value\n" +
                "    state[0] += a;\n" +
                "    state[1] += b;\n" +
                "    state[2] += c;\n" +
                "    state[3] += d;\n" +
                "    state[4] += e;\n" +
                "    state[5] += f;\n" +
                "    state[6] += g;\n" +
                "    state[7] += h;\n" +
                "}\n" +
                "\n" +
                "void sha256_hash(const uchar* message, uint msgLen, uchar hash[32]) {\n" +
                "    uint state[8];\n" +
                "    for (int i = 0; i < 8; i++) {\n" +
                "        state[i] = h_init[i];\n" +
                "    }\n" +
                "    \n" +
                "    uchar block[64];\n" +
                "    uint blockCount = 0;\n" +
                "    uint totalLen = msgLen;\n" +
                "    \n" +
                "    // Process full blocks\n" +
                "    while (msgLen >= 64) {\n" +
                "        for (int i = 0; i < 64; i++) {\n" +
                "            block[i] = message[blockCount * 64 + i];\n" +
                "        }\n" +
                "        sha256_transform(state, block);\n" +
                "        msgLen -= 64;\n" +
                "        blockCount++;\n" +
                "    }\n" +
                "    \n" +
                "    // Process final block with padding\n" +
                "    for (int i = 0; i < 64; i++) {\n" +
                "        block[i] = 0;\n" +
                "    }\n" +
                "    \n" +
                "    for (uint i = 0; i < msgLen; i++) {\n" +
                "        block[i] = message[blockCount * 64 + i];\n" +
                "    }\n" +
                "    \n" +
                "    // Append 0x80\n" +
                "    block[msgLen] = 0x80;\n" +
                "    \n" +
                "    // If not enough space for length, process this block and create new one\n" +
                "    if (msgLen >= 56) {\n" +
                "        sha256_transform(state, block);\n" +
                "        for (int i = 0; i < 64; i++) {\n" +
                "            block[i] = 0;\n" +
                "        }\n" +
                "    }\n" +
                "    \n" +
                "    // Append length in bits (big-endian)\n" +
                "    ulong bitLen = (ulong)totalLen * 8;\n" +
                "    block[63] = bitLen & 0xFF;\n" +
                "    block[62] = (bitLen >> 8) & 0xFF;\n" +
                "    block[61] = (bitLen >> 16) & 0xFF;\n" +
                "    block[60] = (bitLen >> 24) & 0xFF;\n" +
                "    block[59] = (bitLen >> 32) & 0xFF;\n" +
                "    block[58] = (bitLen >> 40) & 0xFF;\n" +
                "    block[57] = (bitLen >> 48) & 0xFF;\n" +
                "    block[56] = (bitLen >> 56) & 0xFF;\n" +
                "    \n" +
                "    sha256_transform(state, block);\n" +
                "    \n" +
                "    // Produce final hash (big-endian)\n" +
                "    for (int i = 0; i < 8; i++) {\n" +
                "        hash[i * 4]     = (state[i] >> 24) & 0xFF;\n" +
                "        hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;\n" +
                "        hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;\n" +
                "        hash[i * 4 + 3] = state[i] & 0xFF;\n" +
                "    }\n" +
                "}\n" +
                "\n" +
                "__kernel void sha256Pow(\n" +
                "    __global const uchar* prefix,\n" +
                "    const uint prefixLen,\n" +
                "    __global const uchar* target,\n" +
                "    const ulong startNonce,\n" +
                "    const ulong batchSize,\n" +
                "    __global int* foundFlag,\n" +
                "    __global ulong* resultNonce)\n" +
                "{\n" +
                "    size_t gid = get_global_id(0);\n" +
                "    ulong nonce = startNonce + gid;\n" +
                "    \n" +
                "    // Convert nonce to string\n" +
                "    uchar nonceStr[20];\n" +
                "    int nonceLen = 0;\n" +
                "    \n" +
                "    if (nonce == 0) {\n" +
                "        nonceStr[0] = '0';\n" +
                "        nonceLen = 1;\n" +
                "    } else {\n" +
                "        ulong temp = nonce;\n" +
                "        // Generate digits in reverse\n" +
                "        while (temp > 0) {\n" +
                "            nonceStr[nonceLen++] = '0' + (temp % 10);\n" +
                "            temp /= 10;\n" +
                "        }\n" +
                "        // Reverse the digits\n" +
                "        for (int i = 0; i < nonceLen / 2; i++) {\n" +
                "            uchar t = nonceStr[i];\n" +
                "            nonceStr[i] = nonceStr[nonceLen - 1 - i];\n" +
                "            nonceStr[nonceLen - 1 - i] = t;\n" +
                "        }\n" +
                "    }\n" +
                "    \n" +
                "    // Construct full message: prefix + nonce string\n" +
                "    uchar msg[128];\n" +
                "    for (int i = 0; i < prefixLen; i++) {\n" +
                "        msg[i] = prefix[i];\n" +
                "    }\n" +
                "    for (int i = 0; i < nonceLen; i++) {\n" +
                "        msg[prefixLen + i] = nonceStr[i];\n" +
                "    }\n" +
                "    \n" +
                "    uint totalLen = prefixLen + nonceLen;\n" +
                "    \n" +
                "    // Calculate SHA-256\n" +
                "    uchar hash[32];\n" +
                "    sha256_hash(msg, totalLen, hash);\n" +
                "    \n" +
                "    // Compare with target\n" +
                "    int ok = 1;\n" +
                "    for (int i = 0; i < 32; i++) {\n" +
                "        if (hash[i] > target[i]) {\n" +
                "            ok = 0;\n" +
                "            break;\n" +
                "        }\n" +
                "        if (hash[i] < target[i]) {\n" +
                "            break;\n" +
                "        }\n" +
                "    }\n" +
                "    \n" +
                "    if (ok && atomic_cmpxchg(foundFlag, 0, 1) == 0) {\n" +
                "        *resultNonce = nonce;\n" +
                "    }\n" +
                "}\n";
    }
}