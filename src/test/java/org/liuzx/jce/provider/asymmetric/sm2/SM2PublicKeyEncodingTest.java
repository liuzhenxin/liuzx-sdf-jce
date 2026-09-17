package org.liuzx.jce.provider.asymmetric.sm2;

import org.junit.jupiter.api.Test;
import org.liuzx.jce.jna.structure.ECCrefPublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class SM2PublicKeyEncodingTest {

    @Test
    void internalPublicComponentRemainsX509Encodable() throws Exception {
        ECCrefPublicKey ref = new ECCrefPublicKey();
        ref.bits = 256;
        byte[] x = hex("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7");
        byte[] y = hex("bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0");
        System.arraycopy(x, 0, ref.x, ref.x.length - x.length, x.length);
        System.arraycopy(y, 0, ref.y, ref.y.length - y.length, y.length);

        SM2PublicKey key = new SM2PublicKey(1, ref);
        byte[] encoded = key.getEncoded();

        assertNotNull(encoded);
        assertEquals("X.509", key.getFormat());
        assertEquals(0x30, encoded[0] & 0xff);
        assertArrayEquals(encoded, key.getEncoded());
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }
}
