package org.liuzx.jce.provider.random;

import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.session.SDFSession;
import org.liuzx.jce.provider.session.SDFSessionManager;

import java.security.ProviderException;
import java.security.SecureRandomSpi;

/**
 * A SecureRandomSpi implementation that gets random data from the HSM
 * via SDF_GenerateRandom.
 */
public class SDFSecureRandomSpi extends SecureRandomSpi {

    private final SDFSessionManager sessionManager;

    public SDFSecureRandomSpi() {
        this.sessionManager = SDFSessionManager.getInstance();
    }

    /**
     * Seeding is not supported as the HSM provides its own entropy.
     */
    @Override
    protected void engineSetSeed(byte[] seed) {
        // Hardware-based RNG does not require/allow external seeding.
    }

    /**
     * Fills the user-provided byte array with random data from the HSM.
     */
    @Override
    protected void engineNextBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return;
        }
        try (SDFSession session = sessionManager.borrowSession()) {
            SDFLibrary sdf = SDFLibrary.getInstance();
            int rv = sdf.SDF_GenerateRandom(session.getSessionHandle(), bytes.length, bytes);
            if (rv != 0) {
                throw new ProviderException("SDF_GenerateRandom failed with code: " + rv);
            }
        }
    }

    /**
     * Generates a seed of the given length. In our case, it's just more random data.
     */
    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        if (numBytes <= 0) {
            return new byte[0];
        }
        byte[] seed = new byte[numBytes];
        engineNextBytes(seed);
        return seed;
    }
}
