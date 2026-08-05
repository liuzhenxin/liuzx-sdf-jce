package org.liuzx.jce.provider.asymmetric.dsa;

import org.liuzx.jce.jna.structure.DSArefPrivateKey;
import org.liuzx.jce.provider.util.ASN1Util;

import java.io.IOException;
import java.security.PrivateKey;

public class DSAPrivateKey implements PrivateKey {
    private final DSArefPrivateKey key;
    public DSAPrivateKey(DSArefPrivateKey key) { this.key = key; }
    public DSArefPrivateKey getKey() { return key; }
    @Override public String getAlgorithm() { return "DSA"; }
    @Override public String getFormat() { return "PKCS#8"; }
    @Override public byte[] getEncoded() {
        try {
            return ASN1Util.toDSAPrivateKeyEncoded(key);
        } catch (IOException e) {
            return null;
        }
    }
}
