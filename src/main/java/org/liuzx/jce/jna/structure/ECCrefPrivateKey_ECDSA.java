package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * ECDSA private key structure.
 */
@Structure.FieldOrder({"bits", "K"})
public class ECCrefPrivateKey_ECDSA extends Structure {

    private static final int ECCref_MAX_LEN_ECDSA = 66;

    public int bits;
    public byte[] K = new byte[ECCref_MAX_LEN_ECDSA];

    public ECCrefPrivateKey_ECDSA() {
        super();
    }

    public static class ByReference extends ECCrefPrivateKey_ECDSA implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "K");
    }
}
