package org.liuzx.jce.provider.asymmetric.rsa;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.RSArefPrivateKey;
import org.liuzx.jce.jna.structure.RSArefPublicKey;
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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
 * Supports:
 * - Encryption with internal or external RSA public key.
 * - Decryption with internal or external SDF RSA private key.
 */
public class RSACipherSpi extends CipherSpi {

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private int opmode;

    private Key rsaKey;

    public RSACipherSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.opmode = opmode;
        if (opmode == Cipher.ENCRYPT_MODE) {
            if (!(key instanceof RSAPublicKey) && !(key instanceof SDFRSAPrivateKey)) {
                throw new InvalidKeyException("Encryption requires an RSAPublicKey or an internal SDFRSAPrivateKey.");
            }
        } else if (opmode == Cipher.DECRYPT_MODE) {
            if (!(key instanceof SDFRSAPrivateKey)) {
                throw new InvalidKeyException("Decryption requires an SDFRSAPrivateKey.");
            }
        } else {
            throw new InvalidKeyException("Unsupported opmode: " + opmode);
        }
        this.rsaKey = key;
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
        } catch (Exception e) {
            if (e instanceof BadPaddingException) throw (BadPaddingException) e;
            if (e instanceof IllegalBlockSizeException) throw (IllegalBlockSizeException) e;
            throw new BadPaddingException("RSA operation failed: " + e.getMessage());
        }
    }

    private byte[] doEncrypt(SDFSession session, byte[] data) throws Exception {
        SDFLibrary sdf = sessionManager.getSdfLibrary();
        byte[] output = new byte[4096 / 8]; // Max key size
        IntByReference outputLen = new IntByReference(output.length);
        int rv;

        if (rsaKey instanceof SDFRSAPrivateKey && ((SDFRSAPrivateKey) rsaKey).isInternalKey()) {
            // Use internal public key for encryption
            SDFRSAPrivateKey internalKey = (SDFRSAPrivateKey) rsaKey;
            rv = sdf.SDF_InternalPublicKeyOperation_RSA(session.getSessionHandle(), internalKey.getKeyIndex(), data, data.length, output, outputLen);
            if (rv != 0) throw new SDFException("SDF_InternalPublicKeyOperation_RSA", rv);
        } else {
            // Use external public key for encryption
            RSAPublicKey publicKey;
            if (rsaKey instanceof SDFRSAPrivateKey) {
                publicKey = ((SDFRSAPrivateKey) rsaKey).getPublicKey();
            } else {
                publicKey = (RSAPublicKey) rsaKey;
            }
            RSArefPublicKey.ByReference refPublicKey = convertToSdfPublicKey(publicKey);
            rv = sdf.SDF_ExternalPublicKeyOperation_RSA(session.getSessionHandle(), refPublicKey, data, data.length, output, outputLen);
            if (rv != 0) throw new SDFException("SDF_ExternalPublicKeyOperation_RSA", rv);
        }

        byte[] result = new byte[outputLen.getValue()];
        System.arraycopy(output, 0, result, 0, result.length);
        return result;
    }

    private byte[] doDecrypt(SDFSession session, byte[] data) throws Exception {
        SDFLibrary sdf = sessionManager.getSdfLibrary();
        SDFRSAPrivateKey privateKey = (SDFRSAPrivateKey) this.rsaKey;
        byte[] output = new byte[privateKey.getModulus().bitLength() / 8];
        IntByReference outputLen = new IntByReference(output.length);
        int rv;

        if (privateKey.isInternalKey()) {
            // Decrypt with internal private key
            char[] password = privateKey.getPassword();
            if (password != null && password.length > 0) {
                byte[] pwdBytes = new String(password).getBytes(StandardCharsets.UTF_8);
                rv = sdf.SDF_GetPrivateKeyAccessRight(session.getSessionHandle(), privateKey.getKeyIndex(), pwdBytes, pwdBytes.length);
                if (rv != 0) throw new SDFException("SDF_GetPrivateKeyAccessRight", rv);
            }
            try {
                rv = sdf.SDF_InternalPrivateKeyOperation_RSA(session.getSessionHandle(), privateKey.getKeyIndex(), data, data.length, output, outputLen);
                if (rv != 0) throw new SDFException("SDF_InternalPrivateKeyOperation_RSA", rv);
            } finally {
                if (password != null && password.length > 0) {
                    sdf.SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), privateKey.getKeyIndex());
                }
            }
        } else {
            // Decrypt with external private key
            RSArefPrivateKey.ByReference refPrivateKey = convertToSdfPrivateKey(privateKey);
            rv = sdf.SDF_ExternalPrivateKeyOperation_RSA(session.getSessionHandle(), refPrivateKey, data, data.length, output, outputLen);
            if (rv != 0) throw new SDFException("SDF_ExternalPrivateKeyOperation_RSA", rv);
        }

        byte[] result = new byte[outputLen.getValue()];
        System.arraycopy(output, 0, result, 0, result.length);
        return result;
    }

    private RSArefPublicKey.ByReference convertToSdfPublicKey(RSAPublicKey publicKey) {
        RSArefPublicKey.ByReference ref = new RSArefPublicKey.ByReference();
        ref.bits = publicKey.getModulus().bitLength();
        copyToSdfBuffer(publicKey.getModulus(), ref.m, 512);
        copyToSdfBuffer(publicKey.getPublicExponent(), ref.e, 512);
        return ref;
    }

    private RSArefPrivateKey.ByReference convertToSdfPrivateKey(SDFRSAPrivateKey privateKey) {
        RSArefPrivateKey.ByReference ref = new RSArefPrivateKey.ByReference();
        ref.bits = privateKey.getModulus().bitLength();
        int keyBytes = (ref.bits + 7) / 8;
        int primeBytes = (keyBytes + 1) / 2;

        copyToSdfBuffer(privateKey.getModulus(), ref.m, 512);
        copyToSdfBuffer(privateKey.getPublicExponent(), ref.e, 512);
        copyToSdfBuffer(privateKey.getPrivateExponent(), ref.d, 512);
        copyToSdfBuffer(privateKey.getPrimeP(), ref.p, 256);
        copyToSdfBuffer(privateKey.getPrimeQ(), ref.q, 256);
        copyToSdfBuffer(privateKey.getPrimeExponentP(), ref.dp, 256);
        copyToSdfBuffer(privateKey.getPrimeExponentQ(), ref.dq, 256);
        copyToSdfBuffer(privateKey.getCrtCoefficient(), ref.qinv, 256);
        return ref;
    }

    private void copyToSdfBuffer(BigInteger value, byte[] buffer, int bufferSize) {
        byte[] bytes = value.toByteArray();
        int srcOffset = 0;
        if (bytes[0] == 0 && bytes.length > 1) {
            srcOffset = 1;
        }
        int length = bytes.length - srcOffset;
        int destOffset = bufferSize - length;
        System.arraycopy(bytes, srcOffset, buffer, destOffset, length);
    }

    // --- Boilerplate CipherSpi methods ---
    @Override protected void engineSetMode(String mode) throws NoSuchAlgorithmException {}
    @Override protected void engineSetPadding(String padding) throws NoSuchPaddingException {}
    @Override protected int engineGetBlockSize() { return 0; }
    @Override protected int engineGetOutputSize(int inputLen) { return (rsaKey instanceof RSAPublicKey) ? (((RSAPublicKey)rsaKey).getModulus().bitLength() + 7) / 8 : 512; }
    @Override protected byte[] engineGetIV() { return null; }
    @Override protected AlgorithmParameters engineGetParameters() { return null; }
    @Override protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException { engineInit(opmode, key, random); }
    @Override protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException { engineInit(opmode, key, random); }
    @Override protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) { buffer.write(input, inputOffset, inputLen); return new byte[0]; }
    @Override protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException { buffer.write(input, inputOffset, inputLen); return 0; }
    @Override protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException { byte[] result = engineDoFinal(input, inputOffset, inputLen); if (output.length - outputOffset < result.length) { throw new ShortBufferException("Output buffer is too short."); } System.arraycopy(result, 0, output, outputOffset, result.length); return result.length; }
}
