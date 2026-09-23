package org.liuzx.jce.api;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 签名语义：摘要长度校验（无硬件）+ 真机签名产物形态（有硬件时）。
 */
class SdfDeviceSignatureSemanticsTest {

    @Test
    void digestLengthMustBeExactly32() {
        assertEquals(SdfErrorCategory.OPERATION_FAILED,
                assertThrows(SdfException.class, () -> SdfDeviceImpl.validateDigestLength(null)).category());
        assertEquals(SdfErrorCategory.OPERATION_FAILED,
                assertThrows(SdfException.class, () -> SdfDeviceImpl.validateDigestLength(new byte[31])).category());
        assertEquals(SdfErrorCategory.OPERATION_FAILED,
                assertThrows(SdfException.class, () -> SdfDeviceImpl.validateDigestLength(new byte[33])).category());
        assertDoesNotThrow(() -> SdfDeviceImpl.validateDigestLength(new byte[32]));
    }

    @Test
    void sm2SignaturesAre64BytesAndRsaMatchesModulus() {
        Integer sm2Index = keyIndex("liuzx.test.sm2.sign.index", "SMOKE_SM2_SIGN_INDEX");
        Integer rsaIndex = keyIndex("liuzx.test.rsa.sign.index", "SMOKE_RSA_SIGN_INDEX");
        Assumptions.assumeTrue(sm2Index != null || rsaIndex != null,
                "set liuzx.test.sm2.sign.index/SMOKE_SM2_SIGN_INDEX or RSA equivalent to run hardware signing");

        SdfDevice device;
        try {
            device = SdfDevices.open();
        } catch (SdfException e) {
            Assumptions.assumeTrue(false, "no SDF device available: " + e.category());
            return;
        }
        try {
            byte[] message = "liuzx-sdf-jce facade signing".getBytes();
            if (sm2Index != null) {
                byte[] signature = device.signSm2(sm2Index.intValue(), message, null);
                assertEquals(64, signature.length);
                byte[] digestSignature = device.signSm2Digest(sm2Index.intValue(),
                        java.util.Arrays.copyOf(signature, 32), null);
                assertEquals(64, digestSignature.length);
            }
            if (rsaIndex != null) {
                byte[] signature = device.signRsa(rsaIndex.intValue(), message, null);
                assertNotNull(signature);
                assertTrue(signature.length == 256 || signature.length == 512,
                        "RSA signature length must match modulus (256 or 512), got " + signature.length);
            }
        } finally {
            device.close();
        }
    }

    private static Integer keyIndex(String systemProperty, String environmentVariable) {
        String value = System.getProperty(systemProperty);
        if (value == null || value.trim().isEmpty()) {
            value = System.getenv(environmentVariable);
        }
        if (value == null || value.trim().isEmpty()) {
            return null;
        }
        try {
            return Integer.valueOf(value.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
