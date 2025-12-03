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
    private static final int SM4_BLOCK_SIZE = 16;

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private int opmode;
    private String mode = "ECB";
    private byte[] iv;

    private SDFSession session;
    private Pointer hKeyHandle;

    public SM4CipherSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }
    
    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be a SecretKey instance.");
        }
        if (params != null && !(params instanceof IvParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only IvParameterSpec is supported.");
        }

        this.opmode = opmode;
        this.iv = (params == null) ? null : ((IvParameterSpec) params).getIV();

        if ("CBC".equals(mode) && iv == null && opmode == Cipher.ENCRYPT_MODE) {
            throw new InvalidAlgorithmParameterException("IV is required for CBC encryption.");
        }
        if (iv != null && iv.length != SM4_BLOCK_SIZE) {
            throw new InvalidAlgorithmParameterException("IV length must be " + SM4_BLOCK_SIZE + " bytes.");
        }

        releaseSession();
        this.session = sessionManager.borrowSession();

        try {
            byte[] keyBytes = key.getEncoded();
            Pointer[] phKeyHandle = new Pointer[1];
            int rv = SDFLibrary.getInstance().SDF_ImportKey(session.getSessionHandle(), keyBytes, keyBytes.length, phKeyHandle);
            if (rv != 0) {
                throw new SDFException("SDF_ImportKey", rv);
            }
            this.hKeyHandle = phKeyHandle[0];
        } catch (Exception e) {
            releaseSession();
            if (e instanceof SDFException) throw (SDFException) e;
            throw new InvalidKeyException("Failed to initialize SM4 cipher", e);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        if (this.session == null || this.hKeyHandle == null) {
            throw new IllegalStateException("Cipher has not been initialized correctly.");
        }
        engineUpdate(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        buffer.reset();

        try {
            if (opmode == Cipher.ENCRYPT_MODE) {
                byte[] paddedData = pkcs5Pad(data);
                byte[] out = new byte[paddedData.length];
                IntByReference outLen = new IntByReference();
                int rv = SDFLibrary.getInstance().SDF_Encrypt(session.getSessionHandle(), hKeyHandle, getAlgId(), iv, paddedData, paddedData.length, out, outLen);
                if (rv != 0) {
                    throw new SDFException("SDF_Encrypt", rv);
                }
                return Arrays.copyOf(out, outLen.getValue());
            } else { // DECRYPT_MODE
                if (data.length % SM4_BLOCK_SIZE != 0) {
                    throw new IllegalBlockSizeException("Input data length must be a multiple of block size for decryption.");
                }
                byte[] out = new byte[data.length];
                IntByReference outLen = new IntByReference();
                int rv = SDFLibrary.getInstance().SDF_Decrypt(session.getSessionHandle(), hKeyHandle, getAlgId(), iv, data, data.length, out, outLen);
                if (rv != 0) {
                    throw new SDFException("SDF_Decrypt", rv);
                }
                return pkcs5Unpad(Arrays.copyOf(out, outLen.getValue()));
            }
        } finally {
            releaseSession();
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
    
    // --- Other boilerplate methods ---
    @Override protected void engineSetMode(String mode) throws NoSuchAlgorithmException { String upperMode = mode.toUpperCase(); if (!"ECB".equals(upperMode) && !"CBC".equals(upperMode)) { throw new NoSuchAlgorithmException("Unsupported mode: " + mode); } this.mode = upperMode; }
    @Override protected void engineSetPadding(String padding) throws NoSuchPaddingException { if (!"PKCS5PADDING".equalsIgnoreCase(padding.replace("-", ""))) { throw new NoSuchPaddingException("Unsupported padding scheme: " + padding); } }
    @Override protected int engineGetBlockSize() { return SM4_BLOCK_SIZE; }
    @Override protected int engineGetOutputSize(int inputLen) { int total = buffer.size() + inputLen; return (total / SM4_BLOCK_SIZE + 1) * SM4_BLOCK_SIZE; }
    @Override protected byte[] engineGetIV() { return (iv == null) ? null : iv.clone(); }
    @Override protected AlgorithmParameters engineGetParameters() { return null; }
    @Override protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException { try { engineInit(opmode, key, (AlgorithmParameterSpec) null, random); } catch (InvalidAlgorithmParameterException e) { throw new InvalidKeyException("Failed to init with null params", e); } }
    @Override protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException { if (params != null) { throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported for SM4 initialization."); } engineInit(opmode, key, (AlgorithmParameterSpec) null, random); }
    @Override protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) { buffer.write(input, inputOffset, inputLen); return new byte[0]; }
    @Override protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException { buffer.write(input, inputOffset, inputLen); return 0; }
    @Override protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException { byte[] result = engineDoFinal(input, inputOffset, inputLen); if (output.length - outputOffset < result.length) { throw new ShortBufferException("Output buffer too short"); } System.arraycopy(result, 0, output, outputOffset, result.length); return result.length; }
    private void releaseSession() { if (this.hKeyHandle != null && this.session != null) { SDFLibrary.getInstance().SDF_DestroyKey(this.session.getSessionHandle(), this.hKeyHandle); this.hKeyHandle = null; } if (this.session != null) { this.session.close(); this.session = null; } }
    private int getAlgId() { return "CBC".equals(mode) ? SGD_SM4_CBC : SGD_SM4_ECB; }
}
