package org.liuzx.jce.provider.asymmetric.sm2;

import org.liuzx.jce.jna.structure.ECCrefPrivateKey;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.util.ASN1Util;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.ProviderException;

public class SM2PrivateKey implements PrivateKey {

    private final ECCrefPrivateKey eccPrivateKey;
    private final ECCrefPublicKey eccPublicKey; // Corresponding public key
    private final int keyIndex;
    private final boolean isInternal;
    private final char[] password;
    private byte[] encoded;

    /** Constructor for an external, exportable private key. */
    public SM2PrivateKey(ECCrefPrivateKey eccPrivateKey, ECCrefPublicKey eccPublicKey) {
        this.eccPrivateKey = eccPrivateKey;
        this.eccPublicKey = eccPublicKey;
        this.keyIndex = 0;
        this.isInternal = false;
        this.password = null;
    }

    /** Constructor for an internal private key with a password and its public key. */
    public SM2PrivateKey(int keyIndex, char[] password, ECCrefPublicKey eccPublicKey) {
        this.eccPrivateKey = null;
        this.eccPublicKey = eccPublicKey;
        this.keyIndex = keyIndex;
        this.isInternal = true;
        this.password = (password == null) ? null : password.clone();
    }
    
    /** Constructor for an internal private key without a password. */
    public SM2PrivateKey(int keyIndex, ECCrefPublicKey eccPublicKey) {
        this(keyIndex, null, eccPublicKey);
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
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
                this.encoded = ASN1Util.toPKCS8PrivateKey(this.eccPrivateKey, this.eccPublicKey);
            } catch (IOException e) {
                throw new ProviderException("Failed to encode SM2 private key to PKCS#8 format", e);
            }
        }
        return encoded.clone();
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

    public ECCrefPrivateKey getEccPrivateKey() {
        if (isInternal) throw new UnsupportedOperationException("Not an external key.");
        return eccPrivateKey;
    }
    
    public ECCrefPublicKey getEccPublicKey() {
        return eccPublicKey;
    }
}
