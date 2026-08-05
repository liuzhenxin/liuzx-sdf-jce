package org.liuzx.jce.provider.asymmetric.dsa;

import org.liuzx.jce.jna.structure.DSArefPublicKey;
import java.security.PublicKey;

public class DSAPublicKey implements PublicKey {
    private final DSArefPublicKey key;
    public DSAPublicKey(DSArefPublicKey key) { this.key = key; }
    public DSArefPublicKey getKey() { return key; }
    @Override public String getAlgorithm() { return "DSA"; }
    @Override public String getFormat() { return "X.509"; }
    @Override public byte[] getEncoded() { return null; }
}
