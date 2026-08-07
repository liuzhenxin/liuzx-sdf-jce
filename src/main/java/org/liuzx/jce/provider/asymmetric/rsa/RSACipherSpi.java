package org.liuzx.jce.provider.asymmetric.rsa;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA CipherSpi implementation using SDF device.
 * <p>
 * Encryption: uses the RSA public key. For external keys, pass an {@link RSAPublicKey}.
 * For internal (hardware) keys, an internal {@link SDFRSAPrivateKey} reference is accepted
 * because it carries the hardware key index needed for the SDF public-key operation — the
 * private-key material itself is never accessed during encryption.
 * <p>
 * Decryption: always requires an {@link SDFRSAPrivateKey} (internal or external).
 */
public class RSACipherSpi extends CipherSpi {

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private int opmode;
    private RSAPublicKey publicKey;          // for output-size estimation and external encrypt
    private SDFRSAPrivateKey privateKey;     // for external decrypt
    private int internalKeyIndex;            // 0 = external key
    private char[] internalPassword;         // for internal-key access right
    protected String padding = "PKCS1Padding"; // "PKCS1Padding" or "NoPadding"; 子类变体在构造时固定
    private SecureRandom secureRandom = new SecureRandom();

    public RSACipherSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        reset();

        if (opmode == Cipher.ENCRYPT_MODE) {
            if (key instanceof RSAPublicKey) {
                this.publicKey = (RSAPublicKey) key;
            } else if (key instanceof SDFRSAPrivateKey && ((SDFRSAPrivateKey) key).isInternalKey()) {
                // Internal key ref: use its key-index for the public-key op on the device.
                SDFRSAPrivateKey sdfKey = (SDFRSAPrivateKey) key;
                this.publicKey = sdfKey.getPublicKey();
                this.internalKeyIndex = sdfKey.getKeyIndex();
                this.internalPassword = sdfKey.getPassword();
            } else {
                throw new InvalidKeyException(
                        "RSA encryption requires an RSAPublicKey or an internal SDFRSAPrivateKey reference.");
            }
        } else if (opmode == Cipher.DECRYPT_MODE) {
            if (!(key instanceof SDFRSAPrivateKey)) {
                throw new InvalidKeyException("RSA decryption requires an SDFRSAPrivateKey.");
            }
            SDFRSAPrivateKey sdfKey = (SDFRSAPrivateKey) key;
            this.publicKey = sdfKey.getPublicKey();
            if (sdfKey.isInternalKey()) {
                this.internalKeyIndex = sdfKey.getKeyIndex();
                this.internalPassword = sdfKey.getPassword();
            } else {
                this.privateKey = sdfKey;
            }
        } else {
            throw new InvalidKeyException("Unsupported opmode: " + opmode);
        }

        this.opmode = opmode;
        if (random != null) {
            this.secureRandom = random;
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        // JCE 的无参 doFinal() 会以 (null, 0, 0) 调用；跳过 update 避免 NPE
        if (input != null) {
            engineUpdate(input, inputOffset, inputLen);
        }
        byte[] data = buffer.toByteArray();
        buffer.reset();

        try (SDFSession session = sessionManager.borrowSession()) {
            if (opmode == Cipher.ENCRYPT_MODE) {
                return doEncrypt(session, data);
            } else {
                return doDecrypt(session, data);
            }
        } catch (Exception e) {
            if (e instanceof BadPaddingException) throw (BadPaddingException) e;
            if (e instanceof IllegalBlockSizeException) throw (IllegalBlockSizeException) e;
            throw new BadPaddingException("RSA operation failed: " + e.getMessage());
        }
    }

    private byte[] doEncrypt(SDFSession session, byte[] data) throws Exception {
        SDFLibrary sdf = sessionManager.getSdfLibrary();
        int keySizeBytes = publicKey.getModulus().bitLength() / 8;
        if (!"NoPadding".equals(padding)) {
            data = pkcs1Pad(data, keySizeBytes);
        }
        byte[] output = new byte[keySizeBytes];
        IntByReference outputLen = new IntByReference(output.length);
        int rv;

        if (internalKeyIndex != 0) {
            // Encryption using internal key index (public-key operation on-device)
            rv = sdf.SDF_InternalPublicKeyOperation_RSA(session.getSessionHandle(),
                    internalKeyIndex, data, data.length, output, outputLen);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_InternalPublicKeyOperation_RSA", rv);
        } else {
            // Encryption using external public key
            rv = sdf.SDF_ExternalPublicKeyOperation_RSA(session.getSessionHandle(),
                    RSAKeyConverter.toSdfPublicKey(publicKey), data, data.length, output, outputLen);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_ExternalPublicKeyOperation_RSA", rv);
        }

        byte[] result = new byte[outputLen.getValue()];
        System.arraycopy(output, 0, result, 0, result.length);
        return result;
    }

    private byte[] doDecrypt(SDFSession session, byte[] data) throws Exception {
        SDFLibrary sdf = sessionManager.getSdfLibrary();
        int keySizeBytes = publicKey.getModulus().bitLength() / 8;
        byte[] output = new byte[keySizeBytes];
        IntByReference outputLen = new IntByReference(output.length);
        int rv;

        if (internalKeyIndex != 0) {
            // Decrypt with internal private key (on-device)
            if (internalPassword != null && internalPassword.length > 0) {
                rv = sessionManager.getPrivateKeyAccessRight(session, internalKeyIndex, internalPassword);
                session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_GetPrivateKeyAccessRight", rv);
            }
            try {
                rv = sdf.SDF_InternalPrivateKeyOperation_RSA(session.getSessionHandle(),
                        internalKeyIndex, data, data.length, output, outputLen);
                session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_InternalPrivateKeyOperation_RSA", rv);
            } finally {
                if (internalPassword != null && internalPassword.length > 0) {
                    sdf.SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), internalKeyIndex);
                }
            }
        } else {
            // Decrypt with external private key
            rv = sdf.SDF_ExternalPrivateKeyOperation_RSA(session.getSessionHandle(),
                    RSAKeyConverter.toSdfPrivateKey(privateKey), data, data.length, output, outputLen);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_ExternalPrivateKeyOperation_RSA", rv);
        }

        byte[] result = new byte[outputLen.getValue()];
        System.arraycopy(output, 0, result, 0, result.length);
        if (!"NoPadding".equals(padding)) {
            result = pkcs1Unpad(result);
        }
        return result;
    }

    // --- PKCS#1 v1.5 (RFC 8017) padding helpers ---

    /**
     * Type-2 encoding: 0x00 0x02 PS 0x00 M, with PS = k - 3 - |M| non-zero random bytes
     * where k = |n| in bytes. The plaintext is limited to k - 11 bytes.
     */
    private byte[] pkcs1Pad(byte[] data, int keySizeBytes) throws IllegalBlockSizeException {
        int maxLen = keySizeBytes - 11;
        if (data.length > maxLen) {
            throw new IllegalBlockSizeException(
                    "RSA/PKCS1 plaintext too long: " + data.length + " bytes, max " + maxLen);
        }
        int psLen = keySizeBytes - data.length - 3;
        byte[] ps = new byte[psLen];
        secureRandom.nextBytes(ps);
        for (int i = 0; i < psLen; i++) {
            while (ps[i] == 0) {
                byte[] one = new byte[1];
                secureRandom.nextBytes(one);
                ps[i] = one[0];
            }
        }
        byte[] em = new byte[keySizeBytes];
        em[1] = 0x02;
        System.arraycopy(ps, 0, em, 2, psLen);
        em[2 + psLen] = 0x00;
        System.arraycopy(data, 0, em, 3 + psLen, data.length);
        return em;
    }

    /**
     * Type-2 decoding: validate the 0x00 0x02 header and the padding string
     * (at least 8 non-zero bytes followed by 0x00), then strip it.
     */
    private byte[] pkcs1Unpad(byte[] em) throws BadPaddingException {
        int k = em.length;
        if (k < 11 || em[0] != 0x00 || em[1] != 0x02) {
            throw new BadPaddingException("RSA/PKCS1: missing 0x00 0x02 header");
        }
        int idx = 2;
        while (idx < k && em[idx] != 0x00) {
            idx++;
        }
        if (idx >= k || (idx - 2) < 8) {
            throw new BadPaddingException("RSA/PKCS1: padding string too short");
        }
        for (int i = 2; i < idx; i++) {
            if (em[i] == 0x00) {
                throw new BadPaddingException("RSA/PKCS1: zero byte inside padding string");
            }
        }
        int mOffset = idx + 1;
        byte[] message = new byte[k - mOffset];
        System.arraycopy(em, mOffset, message, 0, message.length);
        return message;
    }

    // --- SDF structure conversion ---
    // 外部密钥 ↔ SDF 结构体的变长布局转换集中在 {@link RSAKeyConverter}，
    // 加解密与签名共用同一套逻辑。

    private void reset() {
        buffer.reset();
        publicKey = null;
        privateKey = null;
        internalKeyIndex = 0;
        internalPassword = null;
    }

    // --- Boilerplate CipherSpi methods ---

    @Override protected void engineSetMode(String mode) throws NoSuchAlgorithmException {}
    @Override protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        String normalized = padding.replace("-", "").toUpperCase();
        if ("NOPADDING".equals(normalized)) {
            this.padding = "NoPadding";
            return;
        }
        if ("PKCS1PADDING".equals(normalized)) {
            this.padding = "PKCS1Padding";
            return;
        }
        throw new NoSuchPaddingException("Unsupported padding: " + padding);
    }

    // --- 具体的变换变体 ---
    // JCE 对显式注册的完整变换名（如 "RSA/None/NoPadding"）不会回调 engineSetPadding，
    // 因此每个变体必须通过独立 SPI 类在构造时固定 padding。

    /** RSA (默认) / RSA/ECB/PKCS1Padding。 */
    public static class PKCS1 extends RSACipherSpi {
        public PKCS1() {
            this.padding = "PKCS1Padding";
        }
    }

    /** RSA/None/NoPadding — 裸 RSA，不加填充。 */
    public static class NoPadding extends RSACipherSpi {
        public NoPadding() {
            this.padding = "NoPadding";
        }
    }
    @Override protected int engineGetBlockSize() { return 0; }
    @Override protected byte[] engineGetIV() { return null; }
    @Override protected AlgorithmParameters engineGetParameters() { return null; }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (publicKey != null) {
            return (publicKey.getModulus().bitLength() + 7) / 8;
        }
        return 512;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        buffer.write(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException("Output buffer is too short.");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }
}
