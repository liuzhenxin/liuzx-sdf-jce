package org.liuzx.jce.provider.asymmetric.rsa;

import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.SDFConfig;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.RSArefPrivateKey;
import org.liuzx.jce.jna.structure.RSArefPublicKey;

import java.math.BigInteger;
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
            SDFConfig.RsaKeyLayout layout = SDFConfig.getInstance().getRsaKeyLayout();

            // 调用SDF设备生成RSA密钥对
            int rv = sdf.SDF_GenerateKeyPair_RSA(session.getSessionHandle(), this.strength, refPublicKey, refPrivateKey);
            session.checkResult(rv); if (rv != 0) {
                throw new SDFException("SDF_GenerateKeyPair_RSA", rv);
            }

            // 1. 转换公钥
            RSAPublicKey rsaPublicKey = convertToRSAPublicKey(refPublicKey, layout);

            // 2. 转换私钥 (提取所有CRT参数)
            int keyBytes = RSAKeyConverter.keyBytes(refPrivateKey.bits);
            int primeBytes = RSAKeyConverter.primeBytes(keyBytes);
            BigInteger d;
            BigInteger p;
            BigInteger q;
            BigInteger dP;
            BigInteger dQ;
            BigInteger qInv;
            if (layout == SDFConfig.RsaKeyLayout.STANDARD) {
                d = RSAKeyConverter.readRightAligned(refPrivateKey.d, keyBytes);
                p = RSAKeyConverter.readRightAligned(refPrivateKey.p, primeBytes);
                q = RSAKeyConverter.readRightAligned(refPrivateKey.q, primeBytes);
                dP = RSAKeyConverter.readRightAligned(refPrivateKey.dp, primeBytes);
                dQ = RSAKeyConverter.readRightAligned(refPrivateKey.dq, primeBytes);
                qInv = RSAKeyConverter.readRightAligned(refPrivateKey.qinv, primeBytes);
            } else {
                byte[] packed = RSAKeyConverter.combine(refPrivateKey.m, refPrivateKey.e, refPrivateKey.d,
                        refPrivateKey.p, refPrivateKey.q, refPrivateKey.dp, refPrivateKey.dq, refPrivateKey.qinv);
                d = RSAKeyConverter.readPacked(packed, 2 * keyBytes, keyBytes);
                p = RSAKeyConverter.readPacked(packed, 3 * keyBytes, primeBytes);
                q = RSAKeyConverter.readPacked(packed, 3 * keyBytes + primeBytes, primeBytes);
                dP = RSAKeyConverter.readPacked(packed, 3 * keyBytes + 2 * primeBytes, primeBytes);
                dQ = RSAKeyConverter.readPacked(packed, 3 * keyBytes + 3 * primeBytes, primeBytes);
                qInv = RSAKeyConverter.readPacked(packed, 3 * keyBytes + 4 * primeBytes, primeBytes);
            }

            SDFRSAPrivateKey sdfPrivateKey = new SDFRSAPrivateKey(rsaPublicKey, d, p, q, dP, dQ, qInv);

            return new KeyPair(rsaPublicKey, sdfPrivateKey);

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key pair using SDF device", e);
        }
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
        return convertToRSAPublicKey(refPublicKey, SDFConfig.getInstance().getRsaKeyLayout());
    }

    private RSAPublicKey convertToRSAPublicKey(
            RSArefPublicKey refPublicKey, SDFConfig.RsaKeyLayout layout) throws Exception {
        int keyBytes = RSAKeyConverter.keyBytes(refPublicKey.bits);
        BigInteger modulus;
        BigInteger publicExponent;
        if (layout == SDFConfig.RsaKeyLayout.STANDARD) {
            modulus = RSAKeyConverter.readRightAligned(refPublicKey.m, keyBytes);
            publicExponent = RSAKeyConverter.readRightAligned(refPublicKey.e, refPublicKey.e.length);
        } else {
            byte[] packed = RSAKeyConverter.combine(refPublicKey.m, refPublicKey.e);
            modulus = RSAKeyConverter.readPacked(packed, 0, keyBytes);
            publicExponent = RSAKeyConverter.readPacked(packed, keyBytes, keyBytes);
        }

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
}
