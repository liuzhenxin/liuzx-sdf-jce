package org.liuzx.jce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

/**
 * Represents an RSA private key, which can be a reference to an internal key in an SDF device,
 * or an external, exportable key with full CRT parameters.
 */
public class SDFRSAPrivateKey implements RSAPrivateCrtKey {

    private final RSAPublicKey publicKey;
    private final boolean isInternal;

    // For internal keys
    private final int keyIndex;
    private final char[] password;

    // For external keys (CRT parameters)
    private final BigInteger privateExponent; // d
    private final BigInteger primeP;          // p
    private final BigInteger primeQ;          // q
    private final BigInteger primeExponentP;  // dP
    private final BigInteger primeExponentQ;  // dQ
    private final BigInteger crtCoefficient;  // qInv

    private transient byte[] encoded;

    /**
     * Constructor for an internal SDF RSA private key reference.
     */
    public SDFRSAPrivateKey(int keyIndex, char[] password, RSAPublicKey publicKey) {
        this.isInternal = true;
        this.keyIndex = keyIndex;
        this.password = (password == null) ? null : password.clone();
        this.publicKey = publicKey;
        // CRT parameters are unknown for internal keys
        this.privateExponent = null;
        this.primeP = null;
        this.primeQ = null;
        this.primeExponentP = null;
        this.primeExponentQ = null;
        this.crtCoefficient = null;
    }

    /**
     * Constructor for an external (software) RSA private key with full CRT parameters.
     */
    public SDFRSAPrivateKey(RSAPublicKey publicKey, BigInteger privateExponent, BigInteger primeP, BigInteger primeQ,
                            BigInteger primeExponentP, BigInteger primeExponentQ, BigInteger crtCoefficient) {
        this.isInternal = false;
        this.publicKey = publicKey;
        this.privateExponent = privateExponent;
        this.primeP = primeP;
        this.primeQ = primeQ;
        this.primeExponentP = primeExponentP;
        this.primeExponentQ = primeExponentQ;
        this.crtCoefficient = crtCoefficient;
        this.keyIndex = 0;
        this.password = null;
    }

    public boolean isInternalKey() {
        return isInternal;
    }

    public int getKeyIndex() {
        if (!isInternal) throw new UnsupportedOperationException("Not an internal key.");
        return keyIndex;
    }

    public char[] getPassword() {
        if (!isInternal) throw new UnsupportedOperationException("Not an internal key.");
        return (password == null) ? null : password.clone();
    }
    
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public BigInteger getModulus() {
        return publicKey.getModulus();
    }
    
    @Override
    public BigInteger getPublicExponent() {
        return publicKey.getPublicExponent();
    }

    @Override
    public BigInteger getPrivateExponent() {
        if (isInternal) throw new UnsupportedOperationException("Private exponent is not available for an internal SDF key.");
        return privateExponent;
    }

    @Override
    public BigInteger getPrimeP() {
        if (isInternal) throw new UnsupportedOperationException("CRT parameter p is not available for an internal SDF key.");
        return primeP;
    }

    @Override
    public BigInteger getPrimeQ() {
        if (isInternal) throw new UnsupportedOperationException("CRT parameter q is not available for an internal SDF key.");
        return primeQ;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        if (isInternal) throw new UnsupportedOperationException("CRT parameter dP is not available for an internal SDF key.");
        return primeExponentP;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        if (isInternal) throw new UnsupportedOperationException("CRT parameter dQ is not available for an internal SDF key.");
        return primeExponentQ;
    }

    @Override
    public BigInteger getCrtCoefficient() {
        if (isInternal) throw new UnsupportedOperationException("CRT parameter qInv is not available for an internal SDF key.");
        return crtCoefficient;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public String getFormat() {
        return isInternal ? null : "PKCS#8";
    }

    @Override
    public synchronized byte[] getEncoded() {
        if (isInternal) {
            return null;
        }
        if (encoded == null) {
            try {
                RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                    getModulus(), getPublicExponent(), getPrivateExponent(),
                    getPrimeP(), getPrimeQ(), getPrimeExponentP(), getPrimeExponentQ(), getCrtCoefficient()
                );
                KeyFactory kf = KeyFactory.getInstance("RSA");
                RSAPrivateKey rsaPriv = (RSAPrivateKey) kf.generatePrivate(keySpec);
                this.encoded = rsaPriv.getEncoded();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new RuntimeException("Failed to encode external RSA key", ex);
            }
        }
        return encoded.clone();
    }
}
