package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * EdDSA signature structure.
 */
@Structure.FieldOrder({"r", "s"})
public class ECCSignature_EDDSA extends Structure {

    private static final int ECCref_MAX_LEN_EDDSA = 32;

    public byte[] r = new byte[ECCref_MAX_LEN_EDDSA];
    public byte[] s = new byte[ECCref_MAX_LEN_EDDSA];

    public ECCSignature_EDDSA() {
        super();
    }

    public static class ByReference extends ECCSignature_EDDSA implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("r", "s");
    }
}
