package org.liuzx.jce.provider.asymmetric.eddsa;

import org.liuzx.jce.jna.structure.ECCrefPrivateKey_EDDSA;
import org.liuzx.jce.provider.util.ASN1Util;

import java.io.IOException;
import java.security.PrivateKey;

public class EdDSAPrivateKey implements PrivateKey {
    private final ECCrefPrivateKey_EDDSA key;
    public EdDSAPrivateKey(ECCrefPrivateKey_EDDSA key) { this.key = key; }
    public ECCrefPrivateKey_EDDSA getKey() { return key; }
    @Override public String getAlgorithm() { return "EdDSA"; }
    @Override public String getFormat() { return "PKCS#8"; }
    @Override public byte[] getEncoded() {
        try {
            return ASN1Util.toEd25519PrivateKeyEncoded(key.pri);
        } catch (IOException e) {
            return null;
        }
    }
}
