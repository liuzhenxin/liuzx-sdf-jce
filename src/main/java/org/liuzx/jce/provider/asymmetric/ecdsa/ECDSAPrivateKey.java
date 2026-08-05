package org.liuzx.jce.provider.asymmetric.ecdsa;

import org.liuzx.jce.jna.structure.ECCrefPrivateKey_ECDSA;

import java.security.PrivateKey;

public class ECDSAPrivateKey implements PrivateKey {
    private final ECCrefPrivateKey_ECDSA key;
    public ECDSAPrivateKey(ECCrefPrivateKey_ECDSA key) { this.key = key; }
    public ECCrefPrivateKey_ECDSA getKey() { return key; }
    @Override public String getAlgorithm() { return "ECDSA"; }
    @Override public String getFormat() { return null; }
    @Override public byte[] getEncoded() { return null; }
}
