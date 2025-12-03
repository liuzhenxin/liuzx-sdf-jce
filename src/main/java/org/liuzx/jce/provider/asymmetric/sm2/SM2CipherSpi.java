package org.liuzx.jce.provider.asymmetric.sm2;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCCipher;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.provider.util.ASN1Util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM2CipherSpi extends CipherSpi {

    private static final int SGD_SM2_3 = 0x00020800; // SM2 encryption algorithm ID

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private int opmode;

    private SM2PublicKey sm2PublicKey;
    private SM2PrivateKey sm2PrivateKey;

    public SM2CipherSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.opmode = opmode;
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (!(key instanceof SM2PublicKey)) {
                throw new InvalidKeyException("Encryption requires an SM2PublicKey.");
            }
            this.sm2PublicKey = (SM2PublicKey) key;
            this.sm2PrivateKey = null;
        } else if (opmode == Cipher.DECRYPT_MODE) {
            if (!(key instanceof SM2PrivateKey)) {
                throw new InvalidKeyException("Decryption requires an SM2PrivateKey.");
            }
            this.sm2PrivateKey = (SM2PrivateKey) key;
            this.sm2PublicKey = null;
        } else {
            throw new InvalidKeyException("Unsupported opmode: " + opmode);
        }
        buffer.reset();
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        engineUpdate(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        buffer.reset();

        try (SDFSession session = sessionManager.borrowSession()) {
            if (opmode == Cipher.ENCRYPT_MODE) {
                return doEncrypt(session, data);
            } else {
                return doDecrypt(session, data);
            }
        } catch (IOException e) {
            throw new SDFException("ASN.1 encoding/decoding failed", -1);
        } catch (Exception e) {
            if (e instanceof BadPaddingException) throw (BadPaddingException) e;
            if (e instanceof SDFException) throw (SDFException) e;
            throw new BadPaddingException("Decryption failed: " + e.getMessage());
        }
    }

    private byte[] doEncrypt(SDFSession session, byte[] data) throws IOException {
        SDFLibrary sdf = SDFLibrary.getInstance();
        ECCCipher.ByReference eccCipher = new ECCCipher.ByReference();

        int rv = sdf.SDF_ExternalEncrypt_ECC(session.getSessionHandle(), SGD_SM2_3, sm2PublicKey.getEccPublicKey(), data, data.length, eccCipher);
        if (rv != 0) {
            throw new SDFException("SDF_ExternalEncrypt_ECC", rv);
        }
        return ASN1Util.toASN1Ciphertext(eccCipher);
    }

    private byte[] doDecrypt(SDFSession session, byte[] data) throws BadPaddingException {
        SDFLibrary sdf = SDFLibrary.getInstance();
        ECCCipher eccCipher = ASN1Util.fromASN1Ciphertext(data);
        byte[] decryptedData = new byte[eccCipher.L];
        IntByReference decryptedLen = new IntByReference();
        int rv;

        if (sm2PrivateKey.isInternalKey()) {
            char[] password = sm2PrivateKey.getPassword();
            if (password != null && password.length > 0) {
                byte[] pwdBytes = new String(password).getBytes(StandardCharsets.UTF_8);
                rv = sdf.SDF_GetPrivateKeyAccessRight(session.getSessionHandle(), sm2PrivateKey.getKeyIndex(), pwdBytes, pwdBytes.length);
                if (rv != 0) {
                    throw new SDFException("SDF_GetPrivateKeyAccessRight", rv);
                }
            }
            try {
                rv = sdf.SDF_InternalDecrypt_ECC(session.getSessionHandle(), sm2PrivateKey.getKeyIndex(), SGD_SM2_3, eccCipher, decryptedData, decryptedLen);
                if (rv != 0) {
                    throw new SDFException("SDF_InternalDecrypt_ECC", rv);
                }
            } finally {
                if (password != null && password.length > 0) {
                    sdf.SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), sm2PrivateKey.getKeyIndex());
                }
            }
        } else {
            rv = sdf.SDF_ExternalDecrypt_ECC(session.getSessionHandle(), SGD_SM2_3, sm2PrivateKey.getEccPrivateKey(), eccCipher, decryptedData, decryptedLen);
            if (rv != 0) {
                throw new SDFException("SDF_ExternalDecrypt_ECC", rv);
            }
        }

        byte[] result = new byte[decryptedLen.getValue()];
        System.arraycopy(decryptedData, 0, result, 0, result.length);
        return result;
    }

    private static String toHexString(byte[] bytes) {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // --- Other CipherSpi methods (boilerplate) ---
    @Override protected void engineSetMode(String mode) throws NoSuchAlgorithmException {}
    @Override protected void engineSetPadding(String padding) throws NoSuchPaddingException {}
    @Override protected int engineGetBlockSize() { return 0; }
    @Override protected int engineGetOutputSize(int inputLen) { return inputLen + 256; } // Estimate
    @Override protected byte[] engineGetIV() { return null; }
    @Override protected AlgorithmParameters engineGetParameters() { return null; }
    @Override protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException { engineInit(opmode, key, random); }
    @Override protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException { engineInit(opmode, key, random); }
    @Override protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) { buffer.write(input, inputOffset, inputLen); return new byte[0]; }
    @Override protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException { buffer.write(input, inputOffset, inputLen); return 0; }
    @Override protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException { byte[] result = engineDoFinal(input, inputOffset, inputLen); if (output.length - outputOffset < result.length) { throw new ShortBufferException("Output buffer is too short."); } System.arraycopy(result, 0, output, outputOffset, result.length); return result.length; }
}
