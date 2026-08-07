package org.liuzx.jce.provider.asymmetric.rsa;

import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.RSArefPrivateKey;
import org.liuzx.jce.jna.structure.RSArefPublicKey;

import java.math.BigInteger;
import java.util.Arrays;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA密钥对生成器的Spi实现。
 * 支持 "加载" SDF设备内部密钥引用，以及通过SDF设备生成外部RSA密钥对。
 */
public class RSAKeyPairGeneratorSpi extends KeyPairGeneratorSpi {

    private RSAInternalKeyGenParameterSpec internalKeySpec;
    private int strength = 2048;
    private SecureRandom random;
    private final SDFSessionManager sessionManager;

    public RSAKeyPairGeneratorSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.strength = keysize;
        this.random = random;
        this.internalKeySpec = null;
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof RSAInternalKeyGenParameterSpec) {
            this.internalKeySpec = (RSAInternalKeyGenParameterSpec) params;
        } else {
            // 支持标准的RSA参数，例如RSAKeyGenParameterSpec
            // 为简化，此处仅支持我们自定义的内部密钥参数
            throw new InvalidAlgorithmParameterException("Unsupported parameter spec: " + params);
        }
        this.random = random;
    }

    @Override
    public KeyPair generateKeyPair() {
        if (internalKeySpec != null) {
            return loadInternalKeyPair();
        } else {
            return generateSDFKeyPair();
        }
    }

    private KeyPair generateSDFKeyPair() {
        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = sessionManager.getSdfLibrary();
            
            RSArefPublicKey.ByReference refPublicKey = new RSArefPublicKey.ByReference();
            RSArefPrivateKey.ByReference refPrivateKey = new RSArefPrivateKey.ByReference();

            // 调用SDF设备生成RSA密钥对
            int rv = sdf.SDF_GenerateKeyPair_RSA(session.getSessionHandle(), this.strength, refPublicKey, refPrivateKey);
            session.checkResult(rv); if (rv != 0) {
                throw new SDFException("SDF_GenerateKeyPair_RSA", rv);
            }

            // 1. 转换公钥
            RSAPublicKey rsaPublicKey = convertToRSAPublicKey(refPublicKey);

            // 2. 转换私钥 (提取所有CRT参数)
            int keyBytes = (refPrivateKey.bits + 7) / 8;
            int primeBytes = (keyBytes + 1) / 2;

            // 数盾把 RSA 私钥当作变长结构 bits + m[keyBytes] + e[keyBytes] + d[keyBytes] +
            // p[primeBytes] + q[primeBytes] + dp[primeBytes] + dq[primeBytes] +
            // qinv[primeBytes] 写回输出缓冲区，子区间随 keyBytes 平移：对 ≤2048 位密钥，
            // e 落在 m 字段尾部、d 落在 e 字段前段、CRT 参数整体前移；4096 位才与
            // JNA 字段一一对齐。故必须按结构体相对偏移提取，而非按字段名直读。
            BigInteger d = extractSdfPrivateRegion(refPrivateKey, 2 * keyBytes, keyBytes);
            BigInteger p = extractSdfPrivateRegion(refPrivateKey, 3 * keyBytes, primeBytes);
            BigInteger q = extractSdfPrivateRegion(refPrivateKey, 3 * keyBytes + primeBytes, primeBytes);
            BigInteger dP = extractSdfPrivateRegion(refPrivateKey, 3 * keyBytes + 2 * primeBytes, primeBytes);
            BigInteger dQ = extractSdfPrivateRegion(refPrivateKey, 3 * keyBytes + 3 * primeBytes, primeBytes);
            BigInteger qInv = extractSdfPrivateRegion(refPrivateKey, 3 * keyBytes + 4 * primeBytes, primeBytes);

            SDFRSAPrivateKey sdfPrivateKey = new SDFRSAPrivateKey(rsaPublicKey, d, p, q, dP, dQ, qInv);

            return new KeyPair(rsaPublicKey, sdfPrivateKey);

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key pair using SDF device", e);
        }
    }

    /**
     * 按结构体相对偏移提取 RSA 私钥的一个数值子区间。
     *
     * <p>JNA 结构体字段的字节区间（相对 m 字段起点，即 bits 之后的偏移）固定为：
     * m=[0,512) e=[512,1024) d=[1024,1536) p=[1536,1792) q=[1792,2048)
     * dp=[2048,2304) dq=[2304,2560) qinv=[2560,2816)。而数盾库输出的是变长布局
     * bits + m[keyBytes] + e[keyBytes] + d[keyBytes] + p[primeBytes] + ...，
     * 各子区间随 keyBytes 平移。此处按 relOffset 定位到对应字段并拷贝 fieldLen 字节。
     * 各数值右对齐填充子区间（65537 等短值在末尾），从子区间开头读取对恰好填满的值
     * （2048/4096 位的模数、d、p、q）与从末尾读取等价。
     */
    private BigInteger extractSdfPrivateRegion(RSArefPrivateKey refPrivateKey,
            int relOffset, int fieldLen) {
        byte[] target;
        int base;
        if (relOffset < 512) {
            target = refPrivateKey.m;
            base = relOffset;
        } else if (relOffset < 1024) {
            target = refPrivateKey.e;
            base = relOffset - 512;
        } else if (relOffset < 1536) {
            target = refPrivateKey.d;
            base = relOffset - 1024;
        } else if (relOffset < 1792) {
            target = refPrivateKey.p;
            base = relOffset - 1536;
        } else if (relOffset < 2048) {
            target = refPrivateKey.q;
            base = relOffset - 1792;
        } else if (relOffset < 2304) {
            target = refPrivateKey.dp;
            base = relOffset - 2048;
        } else if (relOffset < 2560) {
            target = refPrivateKey.dq;
            base = relOffset - 2304;
        } else {
            target = refPrivateKey.qinv;
            base = relOffset - 2560;
        }
        if (base < 0 || base + fieldLen > target.length) {
            throw new IllegalArgumentException(
                    "RSA private key region out of JNA buffer: bits=" + refPrivateKey.bits
                            + " relOffset=" + relOffset + " fieldLen=" + fieldLen);
        }
        byte[] bytes = new byte[fieldLen];
        System.arraycopy(target, base, bytes, 0, fieldLen);
        return new BigInteger(1, bytes);
    }

    private KeyPair loadInternalKeyPair() {
        int keyIndex = internalKeySpec.getKeyIndex();

        try {
            RSAPublicKey publicKey;
            if (internalKeySpec.hasExternalPublicKey()) {
                // 外部注入了公钥：跳过 SDF 导出。
                // 数盾 SDK 导出函数按 Lite 结构仅支持到 2048 位，4096 位密钥导出会越界崩溃，
                // 必须由调用方提供该索引对应的公钥（见 RSAInternalKeyGenParameterSpec）。
                publicKey = internalKeySpec.getPublicKey();
            } else {
                try (SDFSession session = sessionManager.borrowSession()) {
                    // 从 SDF 设备导出公钥
                    publicKey = exportRSAPublicKey(session, keyIndex);
                }
            }

            // 创建私钥引用，并将公钥传入
            PrivateKey privateKey = new SDFRSAPrivateKey(keyIndex, null, publicKey);

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load internal RSA key pair from SDF device", e);
        }
    }

    private RSAPublicKey exportRSAPublicKey(SDFSession session, int keyIndex) throws Exception {
        SDFLibrary sdf = sessionManager.getSdfLibrary();

        // 先尝试导出签名公钥；若该索引是加密密钥（返回密钥类型错误），回退导出加密公钥。
        // 设备密钥类型（SIGN/ENCRYPT）无法从 RSAInternalKeyGenParameterSpec 得知，故用 fallback。
        //
        // 数盾 SDF 库的 SDF_ExportSignPublicKey_RSA / SDF_ExportEncPublicKey_RSA 按
        // RSArefPublicKey（m[512]/e[512]，支持最大 4096 位）布局填充输出结构：
        // 对 ≤2048 位密钥只写前 4 + 2*keyBytes 字节（等效 Lite 前缀），4096 位才写满
        // 1028 字节。因此接收缓冲区必须用 512 字节的 RSArefPublicKey——若按旧代码
        // 用 m[256] 的 Lite 结构接收 4096 位密钥，bits=4096 → keyBytes=512 →
        // arraycopy 源索引 m.length-keyBytes=-256 越界崩溃，且结构体大小不匹配
        // 会造成原生层堆越界（free(): invalid pointer）。
        RSArefPublicKey.ByReference refPublicKey = new RSArefPublicKey.ByReference();
        int rv = sdf.SDF_ExportSignPublicKey_RSA(session.getSessionHandle(), keyIndex, refPublicKey);
        session.checkResult(rv); if (rv != 0) {
            refPublicKey = new RSArefPublicKey.ByReference();
            rv = sdf.SDF_ExportEncPublicKey_RSA(session.getSessionHandle(), keyIndex, refPublicKey);
            session.checkResult(rv); if (rv != 0) {
                throw new SDFException(
                        "SDF_ExportSignPublicKey_RSA / SDF_ExportEncPublicKey_RSA for key index " + keyIndex, rv);
            }
        }

        return convertToRSAPublicKey(refPublicKey);
    }

    private RSAPublicKey convertToRSAPublicKey(RSArefPublicKey refPublicKey) throws Exception {
        return buildRSAPublicKey(refPublicKey.bits, refPublicKey.m, refPublicKey.e);
    }

    private RSAPublicKey buildRSAPublicKey(int bits, byte[] modulusBuffer, byte[] exponentBuffer) throws Exception {
        int keyBytes = (bits + 7) / 8;
        if (keyBytes > modulusBuffer.length) {
            throw new IllegalArgumentException(
                    "RSA public key too large for buffer: bits=" + bits
                            + " (max " + (modulusBuffer.length * 8) + ")");
        }

        // 数盾 SDF 导出函数返回的模数在缓冲区中左对齐（从 m[0] 开始，大端）。
        // 实测：4096 位密钥 512 字节恰好填满 Ex 缓冲区；2048 位密钥 256 字节位于
        // m[0..255]，m[256..511] 为 0。若按"右对齐取末尾 keyBytes 字节"读取，
        // 2048 位会取到全零 → RSA keys must be at least 512 bits long。
        // 故直接从缓冲区开头拷贝 keyBytes 字节。
        byte[] modulusBytes = new byte[keyBytes];
        System.arraycopy(modulusBuffer, 0, modulusBytes, 0, keyBytes);
        BigInteger modulus = new BigInteger(1, modulusBytes);

        // 指数的位置与密钥位长相关（数盾实测，dump 原始缓冲区确认）：
        //   4096 位：指数位于 e 缓冲区末尾（右对齐，e[508..511] = 65537），m 填满；
        //   2048 位：e 缓冲区全零，指数被放在 m 缓冲区末尾（m[508..511] = 65537）。
        // 故先取 e 缓冲区；若 e 全零（2048 位布局），改为从 m 缓冲区模数之后的尾部提取。
        BigInteger publicExponent;
        if (isAllZero(exponentBuffer)) {
            if (keyBytes >= modulusBuffer.length) {
                throw new IllegalArgumentException(
                        "RSA public key: exponent missing from both buffers (bits=" + bits + ")");
            }
            publicExponent = new BigInteger(1,
                    Arrays.copyOfRange(modulusBuffer, keyBytes, modulusBuffer.length));
        } else {
            publicExponent = new BigInteger(1, exponentBuffer);
        }

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    private static boolean isAllZero(byte[] buffer) {
        for (byte b : buffer) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
