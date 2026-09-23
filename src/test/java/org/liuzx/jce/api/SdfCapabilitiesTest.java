package org.liuzx.jce.api;

import org.junit.jupiter.api.Test;
import org.liuzx.jce.provider.asymmetric.sm2.SM2SignatureSpi;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SM2 UserID 单一来源与 {@link SdfCapabilities} 不可变性。不依赖硬件。
 */
class SdfCapabilitiesTest {

    @Test
    void sm2DefaultUserIdHasSingleSource() {
        assertEquals("1234567812345678", SM2SignatureSpi.DEFAULT_USER_ID_STRING);
        assertFalse(SM2SignatureSpi.DEFAULT_USER_ID_STRING.isEmpty());
    }

    @Test
    void capabilitiesExposeEffectiveUserId() {
        SdfCapabilities capabilities = new SdfCapabilities(
                new HashSet<AlgorithmFamily>(java.util.Arrays.asList(
                        AlgorithmFamily.SM2, AlgorithmFamily.SM3)),
                true,
                SM2SignatureSpi.DEFAULT_USER_ID_STRING,
                16, 16, 5000L);
        assertEquals(SM2SignatureSpi.DEFAULT_USER_ID_STRING, capabilities.sm2DefaultUserId());
        assertTrue(capabilities.sm2DigestSigningSupported());
        assertEquals(16, capabilities.sessionPoolSize());
        assertEquals(5000L, capabilities.borrowTimeoutMillis());
    }

    @Test
    void familiesAreImmutable() {
        Set<AlgorithmFamily> mutable = new HashSet<AlgorithmFamily>();
        mutable.add(AlgorithmFamily.SM2);
        SdfCapabilities capabilities = new SdfCapabilities(
                mutable, true, SM2SignatureSpi.DEFAULT_USER_ID_STRING, 1, 1, 1L);

        assertThrows(UnsupportedOperationException.class,
                () -> capabilities.families().add(AlgorithmFamily.RSA));

        // Mutating the source set after construction must not affect the snapshot.
        mutable.add(AlgorithmFamily.RSA);
        assertFalse(capabilities.families().contains(AlgorithmFamily.RSA));
    }
}
