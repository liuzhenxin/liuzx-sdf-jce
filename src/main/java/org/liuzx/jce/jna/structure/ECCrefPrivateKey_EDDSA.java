package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * EdDSA private key structure.
 */
@Structure.FieldOrder({"bits", "pri"})
public class ECCrefPrivateKey_EDDSA extends Structure {

    private static final int ECCref_MAX_LEN_EDDSA = 32;

    public int bits;
    public byte[] pri = new byte[ECCref_MAX_LEN_EDDSA];

    public ECCrefPrivateKey_EDDSA() {
        super();
    }

    public static class ByReference extends ECCrefPrivateKey_EDDSA implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "pri");
    }
}
