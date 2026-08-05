package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * ECDSA public key structure.
 * Supports up to 521-bit keys (ECCref_MAX_BITS_ECDSA = 521).
 */
@Structure.FieldOrder({"bits", "x", "y"})
public class ECCrefPublicKey_ECDSA extends Structure {

    private static final int ECCref_MAX_LEN_ECDSA = 66; // (521 + 7) / 8

    public int bits;
    public byte[] x = new byte[ECCref_MAX_LEN_ECDSA];
    public byte[] y = new byte[ECCref_MAX_LEN_ECDSA];

    public ECCrefPublicKey_ECDSA() {
        super();
    }

    public static class ByReference extends ECCrefPublicKey_ECDSA implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "x", "y");
    }
}
