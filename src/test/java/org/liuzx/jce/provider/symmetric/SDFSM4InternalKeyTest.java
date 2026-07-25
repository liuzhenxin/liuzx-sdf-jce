package org.liuzx.jce.provider.symmetric;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SDFSM4InternalKeyTest {

    @Test
    public void internalKeyDoesNotExposeEncodedMaterial() {
        SDFSM4InternalKey key = SDFSM4Keys.internalKey(1);

        assertEquals("SM4", key.getAlgorithm());
        assertNull(key.getFormat());
        assertNull(key.getEncoded());
        assertEquals(1, key.getKeyIndex());
        assertEquals(16, key.getKeyLengthBytes());
        assertEquals(16, key.getEncryptedKey().length);
    }

    @Test
    public void internalKeyRequiresPositiveIndex() {
        assertThrows(IllegalArgumentException.class, () -> SDFSM4Keys.internalKey(0));
    }
}
