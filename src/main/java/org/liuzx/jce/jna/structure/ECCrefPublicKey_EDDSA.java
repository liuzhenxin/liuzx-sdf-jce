package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * EdDSA public key structure (Ed25519).
 */
@Structure.FieldOrder({"bits", "pub"})
public class ECCrefPublicKey_EDDSA extends Structure {

    private static final int ECCref_MAX_LEN_EDDSA = 32;

    public int bits;
    public byte[] pub = new byte[ECCref_MAX_LEN_EDDSA];

    public ECCrefPublicKey_EDDSA() {
        super();
    }

    public static class ByReference extends ECCrefPublicKey_EDDSA implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("bits", "pub");
    }
}
