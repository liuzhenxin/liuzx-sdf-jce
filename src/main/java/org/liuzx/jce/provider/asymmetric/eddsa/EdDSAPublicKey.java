package org.liuzx.jce.provider.asymmetric.eddsa;

import org.liuzx.jce.jna.structure.ECCrefPublicKey_EDDSA;
import org.liuzx.jce.provider.util.ASN1Util;

import java.io.IOException;
import java.security.PublicKey;

public class EdDSAPublicKey implements PublicKey {
    private final ECCrefPublicKey_EDDSA key;
    public EdDSAPublicKey(ECCrefPublicKey_EDDSA key) { this.key = key; }
    public ECCrefPublicKey_EDDSA getKey() { return key; }
    @Override public String getAlgorithm() { return "EdDSA"; }
    @Override public String getFormat() { return "X.509"; }
    @Override public byte[] getEncoded() {
        try {
            return ASN1Util.toEd25519PublicKeyEncoded(key.pub);
        } catch (IOException e) {
            return null;
        }
    }
}
