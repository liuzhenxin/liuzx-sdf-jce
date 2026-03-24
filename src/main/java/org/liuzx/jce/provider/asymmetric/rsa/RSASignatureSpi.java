package org.liuzx.jce.provider.asymmetric.rsa;

import com.sun.jna.ptr.IntByReference;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
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
 * 使用SDF设备内部RSA密钥进行签名的SignatureSpi实现。
 * 该实现遵循项目现有的架构模式，直接与SDFSessionManager交互。
 */
public abstract class RSASignatureSpi extends SignatureSpi {

    private final SDFSessionManager sessionManager;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private MessageDigest digest;
    private SDFRSAPrivateKey internalPrivateKey;
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
        this.internalPrivateKey = null;
        this.buffer.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SDFRSAPrivateKey)) {
            throw new InvalidKeyException("Expected an SDFRSAPrivateKey for internal signing.");
        }
        SDFRSAPrivateKey sdfKey = (SDFRSAPrivateKey) privateKey;
        if (!sdfKey.isInternalKey()) {
            throw new InvalidKeyException("Only internal SDFRSAPrivateKey is supported for signing.");
        }
        this.internalPrivateKey = sdfKey;
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
        if (internalPrivateKey == null) {
            throw new SignatureException("Signature not initialized for signing.");
        }
        
        byte[] dataToSign = buffer.toByteArray();
        buffer.reset();

        // RSA签名通常是对数据的摘要进行签名
        byte[] hash = digest.digest(dataToSign);

        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = sessionManager.getSdfLibrary(); // Corrected: get library from manager
            int keyIndex = internalPrivateKey.getKeyIndex();
            char[] password = internalPrivateKey.getPassword();

            // 1. 获取私钥访问权限 (如果需要)
            if (password != null && password.length > 0) {
                byte[] pwdBytes = new String(password).getBytes(StandardCharsets.UTF_8);
                int rv = sdf.SDF_GetPrivateKeyAccessRight(session.getSessionHandle(), keyIndex, pwdBytes, pwdBytes.length);
                if (rv != 0) {
                    throw new SDFException("SDF_GetPrivateKeyAccessRight for RSA key", rv);
                }
            }

            try {
                // 2. 执行内部签名
                byte[] signature = new byte[internalPrivateKey.getModulus().bitLength() / 8];
                IntByReference signatureLength = new IntByReference();
                int rv = sdf.SDF_InternalSign_RSA(session.getSessionHandle(), keyIndex, hash, hash.length, signature, signatureLength);
                if (rv != 0) {
                    throw new SDFException("SDF_InternalSign_RSA", rv);
                }

                byte[] result = new byte[signatureLength.getValue()];
                System.arraycopy(signature, 0, result, 0, result.length);
                return result;

            } finally {
                // 3. 释放私钥访问权限 (如果之前获取过)
                if (password != null && password.length > 0) {
                    sdf.SDF_ReleasePrivateKeyAccessRight(session.getSessionHandle(), keyIndex);
                }
            }
        } catch (Exception e) {
            if (e instanceof SignatureException) throw (SignatureException) e;
            throw new SignatureException("Failed to sign using internal SDF RSA key.", e);
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
