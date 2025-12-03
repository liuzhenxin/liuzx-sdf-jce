package org.liuzx.jce.provider.symmetric;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.exception.SDFException;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SM4KeyGenerator extends KeyGeneratorSpi {

    private static final int SM4_KEY_SIZE_BITS = 128;
    private static final int SM4_KEY_SIZE_BYTES = 16;

    private final SDFSessionManager sessionManager;

    public SM4KeyGenerator() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    @Override
    protected void engineInit(SecureRandom random) {
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("SM4 KeyGenerator does not support AlgorithmParameterSpec");
    }

    @Override
    protected void engineInit(int keysize, SecureRandom random) {
        if (keysize != SM4_KEY_SIZE_BITS) {
            throw new InvalidParameterException("SM4 key size must be " + SM4_KEY_SIZE_BITS + " bits");
        }
    }

    @Override
    protected SecretKey engineGenerateKey() {
        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            
            byte[] randomKey = new byte[SM4_KEY_SIZE_BYTES];
            int rv = sdf.SDF_GenerateRandom(session.getSessionHandle(), SM4_KEY_SIZE_BYTES, randomKey);
            if (rv != 0) {
                throw new SDFException("SDF_GenerateRandom", rv);
            }

            return new SM4SecretKey(randomKey);
        }
    }
}
