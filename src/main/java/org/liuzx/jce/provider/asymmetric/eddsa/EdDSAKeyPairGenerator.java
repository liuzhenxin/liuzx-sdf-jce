package org.liuzx.jce.provider.asymmetric.eddsa;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCrefPrivateKey_EDDSA;
import org.liuzx.jce.jna.structure.ECCrefPublicKey_EDDSA;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class EdDSAKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int SGD_EDDSA = 0x00050000;
    private final SDFSessionManager sessionManager;
    private int keySize = 256;

    public EdDSAKeyPairGenerator() { this.sessionManager = SDFSessionManager.getInstance(); }
    @Override public void initialize(int keysize, SecureRandom random) { this.keySize = keysize; }
    @Override public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException { throw new InvalidAlgorithmParameterException("Not supported"); }

    @Override
    public KeyPair generateKeyPair() {
        try (SDFSession s = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            ECCrefPublicKey_EDDSA.ByReference pub = new ECCrefPublicKey_EDDSA.ByReference();
            ECCrefPrivateKey_EDDSA.ByReference pri = new ECCrefPrivateKey_EDDSA.ByReference();
            int rv = sdf.SDF_GenerateKeyPair_EDDSA(s.getSessionHandle(), SGD_EDDSA, keySize, pub, pri);
            s.checkResult(rv); if (rv != 0) throw new SDFException("SDF_GenerateKeyPair_EDDSA", rv);
            return new KeyPair(new EdDSAPublicKey(pub), new EdDSAPrivateKey(pri));
        }
    }
}
