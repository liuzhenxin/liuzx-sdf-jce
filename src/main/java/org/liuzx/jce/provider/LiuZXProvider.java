package org.liuzx.jce.provider;

import java.security.Provider;

public class LiuZXProvider extends Provider {
    private static final String INFO = "LiuZX JCE provider";
    public static final String PROVIDER_NAME = "liuzx";

    public LiuZXProvider() {
        super(PROVIDER_NAME, 1.0, INFO);

        // --- SecureRandom ---
        put("SecureRandom.SDF", "org.liuzx.jce.provider.random.SDFSecureRandomSpi");

        // --- MessageDigest ---
        put("MessageDigest.SM3",    "org.liuzx.jce.provider.digest.SM3Digest");
        put("MessageDigest.SHA-1",   "org.liuzx.jce.provider.digest.SDFDigest$SHA1");
        put("MessageDigest.SHA-224", "org.liuzx.jce.provider.digest.SDFDigest$SHA224");
        put("MessageDigest.SHA-256", "org.liuzx.jce.provider.digest.SDFDigest$SHA256");
        put("MessageDigest.SHA-384", "org.liuzx.jce.provider.digest.SDFDigest$SHA384");
        put("MessageDigest.SHA-512", "org.liuzx.jce.provider.digest.SDFDigest$SHA512");
        put("MessageDigest.MD5",     "org.liuzx.jce.provider.digest.SDFDigest$MD5");

        // --- SM2 ---
        put("KeyPairGenerator.SM2", "org.liuzx.jce.provider.asymmetric.sm2.SM2KeyPairGenerator");
        put("Signature.SM3withSM2", "org.liuzx.jce.provider.asymmetric.sm2.SM2SignatureSpi");
        put("Cipher.SM2", "org.liuzx.jce.provider.asymmetric.sm2.SM2CipherSpi");
        put("KeyAgreement.SM2", "org.liuzx.jce.provider.asymmetric.sm2.SM2KeyAgreementSpi");

        // --- SM4 ---
        put("KeyGenerator.SM4", "org.liuzx.jce.provider.symmetric.SM4KeyGenerator");
        put("Cipher.SM4", "org.liuzx.jce.provider.symmetric.SM4CipherSpi");
        put("Cipher.SM4/ECB/PKCS5Padding", "org.liuzx.jce.provider.symmetric.SM4CipherSpi$ECB_PKCS5");
        put("Cipher.SM4/CBC/PKCS5Padding", "org.liuzx.jce.provider.symmetric.SM4CipherSpi$CBC_PKCS5");
        put("Cipher.SM4/CFB/PKCS5Padding", "org.liuzx.jce.provider.symmetric.SM4CipherSpi$CFB_PKCS5");
        put("Cipher.SM4/CFB/NoPadding", "org.liuzx.jce.provider.symmetric.SM4CipherSpi$CFB_NoPad");
        put("Cipher.SM4/OFB/PKCS5Padding", "org.liuzx.jce.provider.symmetric.SM4CipherSpi$OFB_PKCS5");
        put("Cipher.SM4/OFB/NoPadding", "org.liuzx.jce.provider.symmetric.SM4CipherSpi$OFB_NoPad");
        put("Mac.SM4MAC", "org.liuzx.jce.provider.mac.SDFMacSpi$SM4");

        // --- RSA ---
        put("KeyPairGenerator.RSA", "org.liuzx.jce.provider.asymmetric.rsa.RSAKeyPairGeneratorSpi");
        put("Signature.SHA1withRSA", "org.liuzx.jce.provider.asymmetric.rsa.RSASignatureSpi$SHA1withRSA");
        put("Signature.SHA256withRSA", "org.liuzx.jce.provider.asymmetric.rsa.RSASignatureSpi$SHA256withRSA");
        put("Signature.SHA512withRSA", "org.liuzx.jce.provider.asymmetric.rsa.RSASignatureSpi$SHA512withRSA");
        put("Signature.MD5withRSA", "org.liuzx.jce.provider.asymmetric.rsa.RSASignatureSpi$MD5withRSA");
        put("Cipher.RSA", "org.liuzx.jce.provider.asymmetric.rsa.RSACipherSpi");
        put("Cipher.RSA/ECB/PKCS1Padding", "org.liuzx.jce.provider.asymmetric.rsa.RSACipherSpi$PKCS1");
        put("Cipher.RSA/None/NoPadding", "org.liuzx.jce.provider.asymmetric.rsa.RSACipherSpi$NoPadding");

        // --- ECDSA ---
        put("KeyPairGenerator.ECDSA", "org.liuzx.jce.provider.asymmetric.ecdsa.ECDSAKeyPairGenerator");
        put("Signature.SHA256withECDSA", "org.liuzx.jce.provider.asymmetric.ecdsa.ECDSASignatureSpi");

        // --- EdDSA ---
        put("KeyPairGenerator.EdDSA", "org.liuzx.jce.provider.asymmetric.eddsa.EdDSAKeyPairGenerator");
        put("Signature.EdDSA", "org.liuzx.jce.provider.asymmetric.eddsa.EdDSASignatureSpi");

        // --- DSA ---
        put("KeyPairGenerator.DSA", "org.liuzx.jce.provider.asymmetric.dsa.DSAKeyPairGenerator");
        put("Signature.SHA1withDSA", "org.liuzx.jce.provider.asymmetric.dsa.DSASignatureSpi");

        // --- HMAC ---
        put("Mac.HmacSM3",    "org.liuzx.jce.provider.mac.SDFHmacSpi$HmacSM3");
        put("Mac.HmacSHA1",   "org.liuzx.jce.provider.mac.SDFHmacSpi$HmacSHA1");
        put("Mac.HmacSHA256", "org.liuzx.jce.provider.mac.SDFHmacSpi$HmacSHA256");
        put("Mac.HmacSHA512", "org.liuzx.jce.provider.mac.SDFHmacSpi$HmacSHA512");
    }
}
