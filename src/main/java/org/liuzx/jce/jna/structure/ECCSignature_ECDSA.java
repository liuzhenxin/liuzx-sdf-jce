package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * ECDSA signature structure.
 */
@Structure.FieldOrder({"r", "s"})
public class ECCSignature_ECDSA extends Structure {

    private static final int ECCref_MAX_LEN_ECDSA = 66;

    public byte[] r = new byte[ECCref_MAX_LEN_ECDSA];
    public byte[] s = new byte[ECCref_MAX_LEN_ECDSA];

    public ECCSignature_ECDSA() {
        super();
    }

    public static class ByReference extends ECCSignature_ECDSA implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("r", "s");
    }
}
