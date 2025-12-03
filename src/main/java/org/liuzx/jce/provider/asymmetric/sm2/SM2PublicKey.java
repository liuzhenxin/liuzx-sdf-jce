package org.liuzx.jce.provider.asymmetric.sm2;

import org.liuzx.jce.jna.structure.ECCrefPublicKey;
import org.liuzx.jce.provider.util.ASN1Util;

import java.io.IOException;
import java.security.ProviderException;
import java.security.PublicKey;

public class SM2PublicKey implements PublicKey {

    private final ECCrefPublicKey eccPublicKey;
    private final int keyIndex;
    private final boolean isInternal;
    private byte[] encoded; // Cache for the encoded form

    public SM2PublicKey(ECCrefPublicKey eccPublicKey) {
        this.eccPublicKey = eccPublicKey;
        this.keyIndex = 0;
        this.isInternal = false;
    }

    public SM2PublicKey(int keyIndex, ECCrefPublicKey eccPublicKey) {
        this.eccPublicKey = eccPublicKey;
        this.keyIndex = keyIndex;
        this.isInternal = true;
    }

    @Override
    public String getAlgorithm() {
        return "SM2";
    }

    @Override
    public String getFormat() {
        return "X.509";
    }

    @Override
    public synchronized byte[] getEncoded() {
        if (isInternal) {
            // Internal keys cannot be reliably encoded as they are not exportable.
            return null;
        }
        if (encoded == null) {
            try {
                this.encoded = ASN1Util.toX509PublicKey(this.eccPublicKey);
            } catch (IOException e) {
                throw new ProviderException("Failed to encode SM2 public key to X.509 format", e);
            }
        }
        return encoded.clone();
    }

    public boolean isInternalKey() {
        return isInternal;
    }

    public int getKeyIndex() {
        if (!isInternal) {
            throw new UnsupportedOperationException("Not an internal key.");
        }
        return keyIndex;
    }

    public ECCrefPublicKey getEccPublicKey() {
        return eccPublicKey;
    }
}
