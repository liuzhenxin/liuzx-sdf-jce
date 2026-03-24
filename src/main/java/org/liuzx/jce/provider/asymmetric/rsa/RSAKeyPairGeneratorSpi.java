package org.liuzx.jce.provider.asymmetric.rsa;

import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.RSArefPrivateKey;
import org.liuzx.jce.jna.structure.RSArefPublicKey;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA密钥对生成器的Spi实现，与项目架构保持一致。
 * 支持 "加载" SDF设备内部密钥引用，以及通过SDF设备生成外部RSA密钥对。
 */
public class RSAKeyPairGeneratorSpi extends KeyPairGenerator {

    private RSAInternalKeyGenParameterSpec internalKeySpec;
    private int strength = 2048;
    private SecureRandom random;
    private final SDFSessionManager sessionManager;

    public RSAKeyPairGeneratorSpi() {
        super("RSA");
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
            if (rv != 0) {
                throw new SDFException("SDF_GenerateKeyPair_RSA", rv);
            }

            // 1. 转换公钥
            RSAPublicKey rsaPublicKey = convertToRSAPublicKey(refPublicKey);

            // 2. 转换私钥 (提取所有CRT参数)
            int keyBytes = (refPrivateKey.bits + 7) / 8;
            int primeBytes = (keyBytes + 1) / 2;

            BigInteger d = extractBigInteger(refPrivateKey.d, 512, keyBytes);
            BigInteger p = extractBigInteger(refPrivateKey.p, 256, primeBytes);
            BigInteger q = extractBigInteger(refPrivateKey.q, 256, primeBytes);
            BigInteger dP = extractBigInteger(refPrivateKey.dp, 256, primeBytes);
            BigInteger dQ = extractBigInteger(refPrivateKey.dq, 256, primeBytes);
            BigInteger qInv = extractBigInteger(refPrivateKey.qinv, 256, primeBytes);

            SDFRSAPrivateKey sdfPrivateKey = new SDFRSAPrivateKey(rsaPublicKey, d, p, q, dP, dQ, qInv);

            return new KeyPair(rsaPublicKey, sdfPrivateKey);

        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key pair using SDF device", e);
        }
    }

    private BigInteger extractBigInteger(byte[] buffer, int bufferSize, int validBytes) {
        byte[] bytes = new byte[validBytes];
        // 假设SDF返回的数据是右对齐的（大端），或者填充在缓冲区的末尾
        // 根据之前的经验，通常是填充在末尾
        System.arraycopy(buffer, bufferSize - validBytes, bytes, 0, validBytes);
        return new BigInteger(1, bytes);
    }

    private KeyPair loadInternalKeyPair() {
        int keyIndex = internalKeySpec.getKeyIndex();
        
        try (SDFSession session = sessionManager.borrowSession()) {
            // 1. 从SDF设备导出公钥
            RSAPublicKey publicKey = exportRSAPublicKey(session, keyIndex);
            
            // 2. 创建私钥引用，并将公钥传入
            PrivateKey privateKey = new SDFRSAPrivateKey(keyIndex, null, publicKey);
            
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load internal RSA key pair from SDF device", e);
        }
    }

    private RSAPublicKey exportRSAPublicKey(SDFSession session, int keyIndex) throws Exception {
        SDFLibrary sdf = sessionManager.getSdfLibrary();
        RSArefPublicKey.ByReference refPublicKey = new RSArefPublicKey.ByReference();
        
        int rv = sdf.SDF_ExportEncPublicKey_RSA(session.getSessionHandle(), keyIndex, refPublicKey);
        if (rv != 0) {
            throw new SDFException("SDF_ExportEncPublicKey_RSA for key index " + keyIndex, rv);
        }

        return convertToRSAPublicKey(refPublicKey);
    }

    private RSAPublicKey convertToRSAPublicKey(RSArefPublicKey refPublicKey) throws Exception {
        // 将SDF公钥结构转换为Java RSAPublicKey
        int keyBytes = (refPublicKey.bits + 7) / 8;
        
        byte[] modulusBytes = new byte[keyBytes];
        System.arraycopy(refPublicKey.m, 512 - keyBytes, modulusBytes, 0, keyBytes);
        
        byte[] exponentBytes = new byte[4]; // 通常是4字节
        System.arraycopy(refPublicKey.e, 512 - exponentBytes.length, exponentBytes, 0, exponentBytes.length);

        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger publicExponent = new BigInteger(1, exponentBytes);

        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }
}
