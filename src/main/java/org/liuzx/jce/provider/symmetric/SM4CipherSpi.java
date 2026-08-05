package org.liuzx.jce.provider.symmetric;

import com.sun.jna.Pointer;
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
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class SM4CipherSpi extends CipherSpi {

    private static final int SGD_SM4_ECB = 0x00000401;
    private static final int SGD_SM4_CBC = 0x00000402;
    private static final int SGD_SM4_CFB = 0x00000404;
    private static final int SGD_SM4_OFB = 0x00000408;
    private static final int SM4_BLOCK_SIZE = 16;

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private int opmode;
    protected String mode = "ECB";
    protected String padding = "PKCS5Padding";
    private byte[] iv;

    // Key material held until engineDoFinal (avoids holding a session open)
    private byte[] rawKey;
    private SDFSM4InternalKey internalKeyInfo;

    public SM4CipherSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    /**
     * JCE 对显式注册的完整变换名（如 "SM4/CBC/PKCS5Padding"）不会回调 engineSetMode/engineSetPadding，
     * 因此每个模式/填充变体通过独立 SPI 子类在构造时固定 mode/padding。
     */
    protected SM4CipherSpi(String mode, String padding) {
        this();
        this.mode = mode;
        this.padding = padding;
    }

    // --- 具体的变换变体 ---

    /** SM4/ECB/PKCS5Padding（"SM4" 默认）。 */
    public static class ECB_PKCS5 extends SM4CipherSpi {
        public ECB_PKCS5() { super("ECB", "PKCS5Padding"); }
    }
    /** SM4/CBC/PKCS5Padding。 */
    public static class CBC_PKCS5 extends SM4CipherSpi {
        public CBC_PKCS5() { super("CBC", "PKCS5Padding"); }
    }
    /** SM4/CFB/PKCS5Padding。 */
    public static class CFB_PKCS5 extends SM4CipherSpi {
        public CFB_PKCS5() { super("CFB", "PKCS5Padding"); }
    }
    /** SM4/CFB/NoPadding。 */
    public static class CFB_NoPad extends SM4CipherSpi {
        public CFB_NoPad() { super("CFB", "NoPadding"); }
    }
    /** SM4/OFB/PKCS5Padding。 */
    public static class OFB_PKCS5 extends SM4CipherSpi {
        public OFB_PKCS5() { super("OFB", "PKCS5Padding"); }
    }
    /** SM4/OFB/NoPadding。 */
    public static class OFB_NoPad extends SM4CipherSpi {
        public OFB_NoPad() { super("OFB", "NoPadding"); }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey instance.");
        }
        if (params != null && !(params instanceof IvParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only IvParameterSpec is supported.");
        }

        this.opmode = opmode;
        this.iv = (params == null) ? null : ((IvParameterSpec) params).getIV();
        this.rawKey = null;
        this.internalKeyInfo = null;

        if (!"ECB".equals(mode) && iv == null) {
            throw new InvalidAlgorithmParameterException("IV is required for " + mode + ".");
        }
        if (iv != null && iv.length != SM4_BLOCK_SIZE) {
            throw new InvalidAlgorithmParameterException("IV length must be " + SM4_BLOCK_SIZE + " bytes.");
        }

        // Store key material locally; actual SDF import happens in engineDoFinal
        if (key instanceof SDFSM4InternalKey) {
            this.internalKeyInfo = (SDFSM4InternalKey) key;
        } else {
            this.rawKey = key.getEncoded();
            if (rawKey == null || rawKey.length == 0) {
                throw new InvalidKeyException("SM4 key encoding is empty. Use SDFSM4InternalKey for internal SDF keys.");
            }
        }

        buffer.reset();
    }

    private Pointer importKeyHandle(SDFSession session) throws SDFException {
        Pointer[] phKeyHandle = new Pointer[1];
        int rv;
        if (internalKeyInfo != null) {
            byte[] encryptedKey = internalKeyInfo.getEncryptedKey();
            if (isEmptyEncryptedKey(encryptedKey)) {
                rv = SDFLibrary.getInstance().SDF_ImportKEK(session.getSessionHandle(),
                        internalKeyInfo.getKeyIndex(), internalKeyInfo.getKeyLengthBytes(), phKeyHandle);
            } else {
                rv = SDFLibrary.getInstance().SDF_ImportKeyWithKEK(session.getSessionHandle(), SGD_SM4_ECB,
                        internalKeyInfo.getKeyIndex(), encryptedKey, internalKeyInfo.getKeyLengthBytes(), phKeyHandle);
            }
            if (rv != 0) {
                throw new SDFException(isEmptyEncryptedKey(encryptedKey) ? "SDF_ImportKEK" : "SDF_ImportKeyWithKEK", rv);
            }
        } else {
            rv = SDFLibrary.getInstance().SDF_ImportKey(session.getSessionHandle(), rawKey, rawKey.length, phKeyHandle);
            if (rv != 0) {
                throw new SDFException("SDF_ImportKey", rv);
            }
        }
        return phKeyHandle[0];
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
            Pointer hKeyHandle = importKeyHandle(session);
            try {
                boolean noPad = "NoPadding".equals(padding);
                boolean blockMode = "ECB".equals(mode) || "CBC".equals(mode);
                if (opmode == Cipher.ENCRYPT_MODE) {
                    if (noPad && blockMode && data.length % SM4_BLOCK_SIZE != 0) {
                        throw new IllegalBlockSizeException(
                                mode + "/NoPadding requires input length to be a multiple of " + SM4_BLOCK_SIZE);
                    }
                    byte[] inputData = noPad ? data : pkcs5Pad(data);
                    byte[] out = new byte[inputData.length + SM4_BLOCK_SIZE];
                    IntByReference outLen = new IntByReference(out.length);
                    int rv = SDFLibrary.getInstance().SDF_Encrypt(session.getSessionHandle(), hKeyHandle,
                            getAlgId(), iv, inputData, inputData.length, out, outLen);
                    if (rv != 0) {
                        throw new SDFException("SDF_Encrypt", rv);
                    }
                    return Arrays.copyOf(out, outLen.getValue());
                } else {
                    if (!noPad && data.length % SM4_BLOCK_SIZE != 0) {
                        throw new IllegalBlockSizeException(
                                "Input data length must be a multiple of block size for decryption.");
                    }
                    byte[] out = new byte[data.length + SM4_BLOCK_SIZE];
                    IntByReference outLen = new IntByReference(out.length);
                    int rv = SDFLibrary.getInstance().SDF_Decrypt(session.getSessionHandle(), hKeyHandle,
                            getAlgId(), iv, data, data.length, out, outLen);
                    if (rv != 0) {
                        throw new SDFException("SDF_Decrypt", rv);
                    }
                    byte[] decrypted = Arrays.copyOf(out, outLen.getValue());
                    return noPad ? decrypted : pkcs5Unpad(decrypted);
                }
            } finally {
                SDFLibrary.getInstance().SDF_DestroyKey(session.getSessionHandle(), hKeyHandle);
            }
        }
    }

    private byte[] pkcs5Pad(byte[] data) {
        int paddingSize = SM4_BLOCK_SIZE - (data.length % SM4_BLOCK_SIZE);
        byte[] padded = new byte[data.length + paddingSize];
        System.arraycopy(data, 0, padded, 0, data.length);
        Arrays.fill(padded, data.length, padded.length, (byte) paddingSize);
        return padded;
    }

    private byte[] pkcs5Unpad(byte[] paddedData) throws BadPaddingException {
        if (paddedData.length == 0) {
            throw new BadPaddingException("Data is empty");
        }
        int paddingSize = paddedData[paddedData.length - 1] & 0xff;
        if (paddingSize > SM4_BLOCK_SIZE || paddingSize == 0) {
            throw new BadPaddingException("Invalid padding size: " + paddingSize);
        }
        for (int i = 1; i <= paddingSize; i++) {
            if (paddedData[paddedData.length - i] != paddingSize) {
                throw new BadPaddingException("Invalid padding data");
            }
        }
        return Arrays.copyOfRange(paddedData, 0, paddedData.length - paddingSize);
    }

    // --- Boilerplate CipherSpi methods ---
    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        String upperMode = mode.toUpperCase();
        if (!"ECB".equals(upperMode) && !"CBC".equals(upperMode) && !"CFB".equals(upperMode) && !"OFB".equals(upperMode)) {
            throw new NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
        this.mode = upperMode;
    }

    @Override
    protected void engineSetPadding(String p) throws NoSuchPaddingException {
        String normalized = p.replace("-", "").toUpperCase();
        if ("NOPADDING".equals(normalized)) {
            this.padding = "NoPadding";
            return;
        }
        if (!"PKCS5PADDING".equals(normalized)) {
            throw new NoSuchPaddingException("Unsupported padding scheme: " + p);
        }
        this.padding = "PKCS5Padding";
    }

    @Override protected int engineGetBlockSize() { return SM4_BLOCK_SIZE; }
    @Override protected int engineGetOutputSize(int inputLen) { return inputLen + SM4_BLOCK_SIZE * 2; }
    @Override protected byte[] engineGetIV() { return (iv == null) ? null : iv.clone(); }
    @Override protected AlgorithmParameters engineGetParameters() { return null; }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("Failed to init with null params", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported for SM4 initialization.");
        }
        engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
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
            throw new ShortBufferException("Output buffer too short");
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    private int getAlgId() {
        switch (mode) {
            case "CBC": return SGD_SM4_CBC;
            case "CFB": return SGD_SM4_CFB;
            case "OFB": return SGD_SM4_OFB;
            default:    return SGD_SM4_ECB;
        }
    }

    private static boolean isEmptyEncryptedKey(byte[] encryptedKey) {
        for (byte b : encryptedKey) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
}
