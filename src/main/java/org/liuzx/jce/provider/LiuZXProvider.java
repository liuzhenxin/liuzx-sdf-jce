package org.liuzx.jce.provider;

import java.security.Provider;

public class LiuZXProvider extends Provider {
    private static final String INFO = "LiuZX JCE provider";
    public static final String PROVIDER_NAME = "liuzx";

    public LiuZXProvider() {
        super(PROVIDER_NAME, 1.0, INFO);
        
        // --- SecureRandom ---
        put("SecureRandom.SDF", "org.liuzx.jce.provider.random.SDFSecureRandomSpi");

        // --- SM3 ---
        put("MessageDigest.SM3", "org.liuzx.jce.provider.digest.SM3Digest");
        
        // --- SM2 ---
        put("KeyPairGenerator.SM2", "org.liuzx.jce.provider.asymmetric.sm2.SM2KeyPairGenerator");
        put("Signature.SM3withSM2", "org.liuzx.jce.provider.asymmetric.sm2.SM2SignatureSpi");
        put("Cipher.SM2", "org.liuzx.jce.provider.asymmetric.sm2.SM2CipherSpi");

        // --- SM4 ---
        put("KeyGenerator.SM4", "org.liuzx.jce.provider.symmetric.SM4KeyGenerator");
        put("Cipher.SM4", "org.liuzx.jce.provider.symmetric.SM4CipherSpi");
        put("Cipher.SM4/ECB/PKCS5Padding", "org.liuzx.jce.provider.symmetric.SM4CipherSpi");
        put("Cipher.SM4/CBC/PKCS5Padding", "org.liuzx.jce.provider.symmetric.SM4CipherSpi");
        
        // --- RSA ---
        put("KeyPairGenerator.RSA", "org.liuzx.jce.provider.asymmetric.rsa.RSAKeyPairGeneratorSpi");
        put("Signature.SHA1withRSA", "org.liuzx.jce.provider.asymmetric.rsa.RSASignatureSpi$SHA1withRSA");
        put("Signature.SHA256withRSA", "org.liuzx.jce.provider.asymmetric.rsa.RSASignatureSpi$SHA256withRSA");
        put("Signature.SHA512withRSA", "org.liuzx.jce.provider.asymmetric.rsa.RSASignatureSpi$SHA512withRSA");
        put("Signature.MD5withRSA", "org.liuzx.jce.provider.asymmetric.rsa.RSASignatureSpi$MD5withRSA");
        put("Cipher.RSA", "org.liuzx.jce.provider.asymmetric.rsa.RSACipherSpi");
        put("Cipher.RSA/ECB/PKCS1Padding", "org.liuzx.jce.provider.asymmetric.rsa.RSACipherSpi");
        put("Cipher.RSA/None/NoPadding", "org.liuzx.jce.provider.asymmetric.rsa.RSACipherSpi");
    }
}
