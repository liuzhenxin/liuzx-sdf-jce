package org.liuzx.jce.provider.asymmetric.rsa;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.RSArefPrivateKey;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPublicKey;

/**
 * 使用 SDF 设备进行 RSA 签名的 SignatureSpi 实现。
 *
 * <p>签名流程与密钥类型无关：软件侧构造 EMSA-PKCS1-v1_5 编码块，再交给设备做裸 RSA
 * 私钥运算——内部密钥用 {@code SDF_InternalPrivateKeyOperation_RSA}（按索引），
 * 外部密钥用 {@code SDF_ExternalPrivateKeyOperation_RSA}（传入 CRT 参数结构体）。
 * 验签在软件中完成。
 */
public abstract class RSASignatureSpi extends SignatureSpi {

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private MessageDigest digest;
    private SDFRSAPrivateKey sdfPrivateKey;
    private RSAPublicKey publicKey;

    protected RSASignatureSpi(MessageDigest digest) {
        this.digest = digest;
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof RSAPublicKey)) {
            throw new InvalidKeyException("Expected an RSAPublicKey for verification.");
        }
        this.publicKey = (RSAPublicKey) publicKey;
        this.sdfPrivateKey = null;
        this.buffer.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SDFRSAPrivateKey)) {
            throw new InvalidKeyException("Expected an SDFRSAPrivateKey for signing.");
        }
        // 支持内部（硬件索索引）与外部（JVM 内存 CRT 参数）两种密钥，
        // 签名都在设备上以裸 RSA 私钥运算完成。
        this.sdfPrivateKey = (SDFRSAPrivateKey) privateKey;
        this.publicKey = null;
        this.buffer.reset();
    }

    @Override
    protected void engineUpdate(byte b) {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (sdfPrivateKey == null) {
            throw new SignatureException("Signature not initialized for signing.");
        }

        byte[] dataToSign = buffer.toByteArray();
        buffer.reset();

        // PKCS#1 v1.5: 软件侧构造 EMSA-PKCS1-v1_5 编码块 (00 01 FF..FF 00 || DigestInfo || hash)，
        // 再交给设备做裸 RSA 私钥运算。这样产物与标准 SHAxxxwithRSA 软件验签互通，
        // 且不依赖设备对 SDF_InternalSign_RSA 入参（原始消息 vs 预摘要）的语义。
        byte[] hash = digest.digest(dataToSign);
        byte[] digestInfo = digestInfoPrefix(digest.getAlgorithm());
        int keySizeBytes = sdfPrivateKey.getModulus().bitLength() / 8;
        byte[] em = pkcs1V15Encode(hash, digestInfo, keySizeBytes);

        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = sessionManager.getSdfLibrary();
            byte[] signature = new byte[keySizeBytes];
            IntByReference signatureLength = new IntByReference(signature.length);
            int rv;

            if (sdfPrivateKey.isInternalKey()) {
                // 内部密钥：按索引在设备上做裸私钥运算，先获取私钥访问权限（若需 PIN）。
                int keyIndex = sdfPrivateKey.getKeyIndex();
                char[] password = sdfPrivateKey.getPassword();
                if (password != null && password.length > 0) {
                    rv = sessionManager.getPrivateKeyAccessRight(session, keyIndex, password);
                    session.checkResult(rv); if (rv != 0) {
                        throw new SDFException("SDF_GetPrivateKeyAccessRight for RSA key", rv);
                    }
                }
                try {
                    rv = sdf.SDF_InternalPrivateKeyOperation_RSA(session.getSessionHandle(), keyIndex,
                            em, em.length, signature, signatureLength);
                    session.checkResult(rv); if (rv != 0) {
                        throw new SDFException("SDF_InternalPrivateKeyOperation_RSA", rv);
                    }
                } finally {
                    if (password != null && password.length > 0) {
                        sdf.SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), keyIndex);
                    }
                }
            } else {
                // 外部密钥：按数盾变长布局构造 RSArefPrivateKey（CRT 参数），设备做裸私钥运算。
                // 与外部解密共用同一转换（见 RSAKeyConverter），两者均已实测通过。
                rv = sdf.SDF_ExternalPrivateKeyOperation_RSA(session.getSessionHandle(),
                        RSAKeyConverter.toSdfPrivateKey(sdfPrivateKey), em, em.length, signature, signatureLength);
                session.checkResult(rv); if (rv != 0) {
                    throw new SDFException("SDF_ExternalPrivateKeyOperation_RSA", rv);
                }
            }

            byte[] result = new byte[signatureLength.getValue()];
            System.arraycopy(signature, 0, result, 0, result.length);
            return result;
        } catch (Exception e) {
            if (e instanceof SignatureException) throw (SignatureException) e;
            throw new SignatureException("Failed to sign using SDF RSA key.", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        if (publicKey == null) {
            throw new SignatureException("Signature not initialized for verification.");
        }
        
        byte[] dataToVerify = buffer.toByteArray();
        buffer.reset();

        try {
            // 验签操作使用标准的Java密码学库在软件中完成，效率更高
            String algorithm = digest.getAlgorithm().replace("-", "") + "withRSA";
            java.security.Signature verifier = java.security.Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(dataToVerify);
            return verifier.verify(sigBytes);
        } catch (Exception e) {
            throw new SignatureException("Error during software-based RSA verification.", e);
        }
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("This signature engine does not support parameters.");
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("This signature engine does not support parameters.");
    }

    // --- PKCS#1 v1.5 (RFC 8017) EMSA encoding helpers ---

    /**
     * DigestInfo DER prefix for each supported hash algorithm (RFC 8017 §9.2).
     */
    private static byte[] digestInfoPrefix(String digestAlg) {
        switch (digestAlg.replace("-", "").toUpperCase()) {
            case "SHA1":
                return new byte[]{(byte) 0x30, (byte) 0x21, (byte) 0x30, (byte) 0x09, (byte) 0x06,
                        (byte) 0x05, (byte) 0x2b, (byte) 0x0e, (byte) 0x03, (byte) 0x02,
                        (byte) 0x1a, (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x14};
            case "SHA256":
                return new byte[]{(byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0d, (byte) 0x06,
                        (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
                        (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x01,
                        (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x20};
            case "SHA512":
                return new byte[]{(byte) 0x30, (byte) 0x51, (byte) 0x30, (byte) 0x0d, (byte) 0x06,
                        (byte) 0x09, (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01,
                        (byte) 0x65, (byte) 0x03, (byte) 0x04, (byte) 0x02, (byte) 0x03,
                        (byte) 0x05, (byte) 0x00, (byte) 0x04, (byte) 0x40};
            case "MD5":
                return new byte[]{(byte) 0x30, (byte) 0x20, (byte) 0x30, (byte) 0x0c, (byte) 0x06,
                        (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0x86,
                        (byte) 0xf7, (byte) 0x0d, (byte) 0x02, (byte) 0x05, (byte) 0x05,
                        (byte) 0x00, (byte) 0x04, (byte) 0x10};
            default:
                throw new IllegalArgumentException("Unsupported digest for RSA signing: " + digestAlg);
        }
    }

    /**
     * EMSA-PKCS1-v1_5 encoding: 0x00 0x01 PS 0x00 || DigestInfo || hash, PS = 0xFF x (k - len(T) - 3).
     */
    private static byte[] pkcs1V15Encode(byte[] hash, byte[] digestInfo, int keySizeBytes) throws SignatureException {
        byte[] t = new byte[digestInfo.length + hash.length];
        System.arraycopy(digestInfo, 0, t, 0, digestInfo.length);
        System.arraycopy(hash, 0, t, digestInfo.length, hash.length);
        if (t.length > keySizeBytes - 11) {
            throw new SignatureException("RSA key too small for " + t.length + "-byte DigestInfo+hash");
        }
        int psLen = keySizeBytes - t.length - 3;
        byte[] em = new byte[keySizeBytes];
        em[1] = 0x01;
        Arrays.fill(em, 2, 2 + psLen, (byte) 0xFF);
        em[2 + psLen] = 0x00;
        System.arraycopy(t, 0, em, 3 + psLen, t.length);
        return em;
    }

    // --- 为不同的摘要算法创建具体的内部类 ---

    public static class SHA1withRSA extends RSASignatureSpi {
        public SHA1withRSA() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("SHA-1"));
        }
    }

    public static class SHA256withRSA extends RSASignatureSpi {
        public SHA256withRSA() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("SHA-256"));
        }
    }

    public static class SHA512withRSA extends RSASignatureSpi {
        public SHA512withRSA() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("SHA-512"));
        }
    }
    
    public static class MD5withRSA extends RSASignatureSpi {
        public MD5withRSA() throws NoSuchAlgorithmException {
            super(MessageDigest.getInstance("MD5"));
        }
    }
}
