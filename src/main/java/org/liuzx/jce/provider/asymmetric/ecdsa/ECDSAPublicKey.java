package org.liuzx.jce.provider.asymmetric.ecdsa;

import org.liuzx.jce.jna.structure.ECCrefPublicKey_ECDSA;
import org.liuzx.jce.provider.util.ASN1Util;

import java.io.IOException;
import java.security.PublicKey;

public class ECDSAPublicKey implements PublicKey {
    private final ECCrefPublicKey_ECDSA key;
    public ECDSAPublicKey(ECCrefPublicKey_ECDSA key) { this.key = key; }
    public ECCrefPublicKey_ECDSA getKey() { return key; }
    @Override public String getAlgorithm() { return "ECDSA"; }
    @Override public String getFormat() { return "X.509"; }
    @Override public byte[] getEncoded() {
        try {
            return ASN1Util.toECDSAPublicKeyEncoded(key);
        } catch (IOException e) {
            return null;
        }
    }
}
