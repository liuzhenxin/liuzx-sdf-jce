package org.liuzx.jce.provider.asymmetric.ecdsa;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.jna.structure.ECCrefPrivateKey_ECDSA;
import org.liuzx.jce.jna.structure.ECCrefPublicKey_ECDSA;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class ECDSAKeyPairGenerator extends KeyPairGeneratorSpi {

    private static final int SGD_ECDSA = 0x00040000;
    private final SDFSessionManager sessionManager;
    private int keySize = 256;

    public ECDSAKeyPairGenerator() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override public void initialize(int keysize, SecureRandom random) { this.keySize = keysize; }
    @Override public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Not supported");
    }

    @Override
    public KeyPair generateKeyPair() {
        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            ECCrefPublicKey_ECDSA.ByReference pub = new ECCrefPublicKey_ECDSA.ByReference();
            ECCrefPrivateKey_ECDSA.ByReference pri = new ECCrefPrivateKey_ECDSA.ByReference();
            int rv = sdf.SDF_GenerateKeyPair_ECDSA(session.getSessionHandle(), SGD_ECDSA, keySize, pub, pri);
            session.checkResult(rv); if (rv != 0) throw new SDFException("SDF_GenerateKeyPair_ECDSA", rv);
            return new KeyPair(new ECDSAPublicKey(pub), new ECDSAPrivateKey(pri));
        }
    }
}
