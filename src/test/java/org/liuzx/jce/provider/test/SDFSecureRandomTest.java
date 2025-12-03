package org.liuzx.jce.provider.test;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.LiuZXProvider;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class SDFSecureRandomTest {

    @BeforeAll
    public static void setup() {
        if (Security.getProvider(LiuZXProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new LiuZXProvider());
        }
    }

    @Test
    public void testSDFSecureRandomInstantiation() throws NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("--- Testing SDF SecureRandom Instantiation ---");
        SecureRandom hsmRandom = SecureRandom.getInstance("SDF", LiuZXProvider.PROVIDER_NAME);
        assertNotNull(hsmRandom, "The SecureRandom instance should not be null.");
        assertEquals(LiuZXProvider.PROVIDER_NAME, hsmRandom.getProvider().getName(), "Provider name should match.");
        System.out.println("Successfully instantiated SecureRandom from provider: " + hsmRandom.getProvider().getName());
    }

    @Test
    public void testNextBytesGeneratesDifferentData() throws NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("\n--- Testing nextBytes() for randomness ---");
        SecureRandom hsmRandom = SecureRandom.getInstance("SDF", LiuZXProvider.PROVIDER_NAME);

        // Generate two separate blocks of random data
        byte[] randomBytes1 = new byte[64];
        hsmRandom.nextBytes(randomBytes1);
        System.out.println("Generated first block of 64 random bytes.");

        byte[] randomBytes2 = new byte[64];
        hsmRandom.nextBytes(randomBytes2);
        System.out.println("Generated second block of 64 random bytes.");

        // A very basic sanity check: the two blocks should not be identical.
        // While a collision is theoretically possible, it's astronomically unlikely for a 64-byte sequence.
        assertFalse(Arrays.equals(randomBytes1, randomBytes2), "Two consecutive calls to nextBytes() should produce different results.");
        System.out.println("Sanity check passed: The two generated blocks are different.");
    }

    @Test
    public void testGenerateSeed() throws NoSuchAlgorithmException, NoSuchProviderException {
        System.out.println("\n--- Testing generateSeed() ---");
        SecureRandom hsmRandom = SecureRandom.getInstance("SDF", LiuZXProvider.PROVIDER_NAME);

        int seedLength = 20;
        byte[] seed = hsmRandom.generateSeed(seedLength);

        assertNotNull(seed, "Generated seed should not be null.");
        assertEquals(seedLength, seed.length, "Generated seed should have the requested length.");
        System.out.println("Successfully generated a seed of length " + seed.length);

        // Also check that it's not all zeros (another sanity check)
        boolean allZeros = true;
        for (byte b : seed) {
            if (b != 0) {
                allZeros = false;
                break;
            }
        }
        assertFalse(allZeros, "Generated seed should not consist of all zeros.");
        System.out.println("Sanity check passed: The generated seed is not all zeros.");
    }
}
