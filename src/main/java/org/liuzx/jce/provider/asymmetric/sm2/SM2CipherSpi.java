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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM2CipherSpi extends CipherSpi {

    private static final int SGD_SM2_3 = 0x00020800; // SM2 encryption algorithm ID
    private static final int MAX_PLAIN_LENGTH = 1024; // ECCCipher.C 缓冲区上限

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private int opmode;

    private SM2PublicKey sm2PublicKey;
    private SM2PrivateKey sm2PrivateKey;
    private int internalKeyIndex; // 0 = external key
    private char[] internalPassword;

    public SM2CipherSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.opmode = opmode;
        this.internalKeyIndex = 0;
        this.internalPassword = null;
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (key instanceof SM2PublicKey) {
                this.sm2PublicKey = (SM2PublicKey) key;
                this.sm2PrivateKey = null;
            } else if (key instanceof SM2PrivateKey && ((SM2PrivateKey) key).isInternalKey()) {
                SM2PrivateKey pk = (SM2PrivateKey) key;
                this.sm2PublicKey = new SM2PublicKey(pk.getKeyIndex(), pk.getEccPublicKey());
                this.sm2PrivateKey = null;
                this.internalKeyIndex = pk.getKeyIndex();
                this.internalPassword = pk.getPassword();
            } else {
                throw new InvalidKeyException("Encryption requires an SM2PublicKey or internal SM2PrivateKey.");
            }
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
        } catch (IOException e) {
            throw new SDFException("ASN.1 encoding/decoding failed", -1);
        } catch (Exception e) {
            if (e instanceof BadPaddingException) throw (BadPaddingException) e;
            if (e instanceof IllegalBlockSizeException) throw (IllegalBlockSizeException) e;
            if (e instanceof SDFException) throw (SDFException) e;
            throw new BadPaddingException("Decryption failed: " + e.getMessage());
        }
    }

    private byte[] doEncrypt(SDFSession session, byte[] data) throws IOException, IllegalBlockSizeException {
        SDFLibrary sdf = SDFLibrary.getInstance();
        ECCCipher.ByReference eccCipher = new ECCCipher.ByReference();
        int rv;

        if (data.length > MAX_PLAIN_LENGTH) {
            throw new IllegalBlockSizeException(
                    "SM2 plaintext too long: " + data.length + " > " + MAX_PLAIN_LENGTH);
        }

        if (internalKeyIndex != 0) {
            // Internal key encryption using SDF_InternalEncrypt_ECC
            if (internalPassword != null && internalPassword.length > 0) {
                rv = sessionManager.getPrivateKeyAccessRight(session, internalKeyIndex, internalPassword);
                session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_GetPrivateKeyAccessRight", rv);
            }
            try {
                rv = sdf.SDF_InternalEncrypt_ECC(session.getSessionHandle(), internalKeyIndex, data, data.length, eccCipher);
                session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_InternalEncrypt_ECC", rv);
            } finally {
                if (internalPassword != null && internalPassword.length > 0) {
                    sdf.SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), internalKeyIndex);
                }
            }
        } else {
            rv = sdf.SDF_ExternalEncrypt_ECC(session.getSessionHandle(), SGD_SM2_3, sm2PublicKey.getEccPublicKey(), data, data.length, eccCipher);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_ExternalEncrypt_ECC", rv);
        }
        return ASN1Util.toASN1Ciphertext(eccCipher);
    }

    private byte[] doDecrypt(SDFSession session, byte[] data) throws BadPaddingException {
        SDFLibrary sdf = SDFLibrary.getInstance();
        ECCCipher eccCipher = ASN1Util.fromASN1Ciphertext(data);
        byte[] decryptedData = new byte[eccCipher.L];
        // puiPlainTextLength 是 in/out 参数：入参=输出缓冲区容量，出参=实际明文长度。
        // 必须初始化为缓冲区容量，否则原生库按容量 0 写入导致越界崩溃（SEGV）。
        IntByReference decryptedLen = new IntByReference(decryptedData.length);
        int rv;

        if (sm2PrivateKey.isInternalKey()) {
            char[] password = sm2PrivateKey.getPassword();
            if (password != null && password.length > 0) {
                rv = sessionManager.getPrivateKeyAccessRight(session, sm2PrivateKey.getKeyIndex(), password);
                session.checkResult(rv); if (rv != 0) {
                    throw new SDFException("SDF_GetPrivateKeyAccessRight", rv);
                }
            }
            try {
                rv = sdf.SDF_InternalDecrypt_ECC(session.getSessionHandle(), sm2PrivateKey.getKeyIndex(), eccCipher, decryptedData, decryptedLen);
                session.checkResult(rv); if (rv != 0) {
                    throw new SDFException("SDF_InternalDecrypt_ECC", rv);
                }
            } finally {
                if (password != null && password.length > 0) {
                    sdf.SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), sm2PrivateKey.getKeyIndex());
                }
            }
        } else {
            rv = sdf.SDF_ExternalDecrypt_ECC(session.getSessionHandle(), SGD_SM2_3, sm2PrivateKey.getEccPrivateKey(), eccCipher, decryptedData, decryptedLen);
            session.checkResult(rv); if (rv != 0) {
                throw new SDFException("SDF_ExternalDecrypt_ECC", rv);
            }
        }

        byte[] result = new byte[decryptedLen.getValue()];
        System.arraycopy(decryptedData, 0, result, 0, result.length);
        return result;
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
