package org.liuzx.jce.api;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 内部公钥导出验收。需要真实设备与有效密钥索引；否则跳过。
 *
 * <p>索引来源：系统属性 {@code liuzx.test.sm2.sign.index} 或环境变量
 * {@code SMOKE_SM2_SIGN_INDEX}。</p>
 */
class SdfDeviceExportKeyTest {

    @Test
    void exportSignPublicKeyReturnsSubjectPublicKeyInfo() {
        Integer keyIndex = resolveKeyIndex();
        Assumptions.assumeTrue(keyIndex != null,
                "set liuzx.test.sm2.sign.index or SMOKE_SM2_SIGN_INDEX to run export test");

        SdfDevice device;
        try {
            device = SdfDevices.open();
        } catch (SdfException e) {
            Assumptions.assumeTrue(false, "no SDF device available: " + e.category());
            return;
        }
        try {
            byte[] encoded = device.exportSignPublicKey(keyIndex.intValue());
            assertNotNull(encoded);
            assertTrue(encoded.length > 0);
            // X.509 SubjectPublicKeyInfo is a DER SEQUENCE.
            assertEquals(0x30, encoded[0] & 0xFF, "expected DER SEQUENCE prefix 0x30");
        } finally {
            device.close();
        }
    }

    private static Integer resolveKeyIndex() {
        String value = System.getProperty("liuzx.test.sm2.sign.index");
        if (value == null || value.trim().isEmpty()) {
            value = System.getenv("SMOKE_SM2_SIGN_INDEX");
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
