package org.liuzx.jce.provider.asymmetric.dsa;

import org.liuzx.jce.jna.structure.DSArefPrivateKey;
import java.security.PrivateKey;

public class DSAPrivateKey implements PrivateKey {
    private final DSArefPrivateKey key;
    public DSAPrivateKey(DSArefPrivateKey key) { this.key = key; }
    public DSArefPrivateKey getKey() { return key; }
    @Override public String getAlgorithm() { return "DSA"; }
    @Override public String getFormat() { return null; }
    @Override public byte[] getEncoded() { return null; }
}
