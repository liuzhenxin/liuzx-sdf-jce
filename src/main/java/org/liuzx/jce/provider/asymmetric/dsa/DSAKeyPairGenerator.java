package org.liuzx.jce.provider.asymmetric.dsa;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.DSArefPrivateKey;
import org.liuzx.jce.jna.structure.DSArefPublicKey;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class DSAKeyPairGenerator extends KeyPairGeneratorSpi {

    private final SDFSessionManager sessionManager;
    private int keySize = 2048;

    public DSAKeyPairGenerator() { this.sessionManager = SDFSessionManager.getInstance(); }
    @Override public void initialize(int keysize, SecureRandom r) { this.keySize = keysize; }
    @Override public void initialize(AlgorithmParameterSpec p, SecureRandom r)
            throws InvalidAlgorithmParameterException { throw new InvalidAlgorithmParameterException("Not supported"); }

    @Override
    public KeyPair generateKeyPair() {
        try (SDFSession s = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            DSArefPublicKey.ByReference pub = new DSArefPublicKey.ByReference();
            DSArefPrivateKey.ByReference pri = new DSArefPrivateKey.ByReference();
            int rv = sdf.SDF_GenerateKeyPair_DSA(s.getSessionHandle(), keySize, pub, pri);
            s.checkResult(rv); if (rv != 0) throw new SDFException("SDF_GenerateKeyPair_DSA", rv);
            return new KeyPair(new DSAPublicKey(pub), new DSAPrivateKey(pri));
        }
    }
}
