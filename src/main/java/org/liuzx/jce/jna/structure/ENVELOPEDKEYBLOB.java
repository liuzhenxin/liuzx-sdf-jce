package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * SDF Enveloped Key Blob (ENVELOPEDKEYBLOB) for digital envelope operations.
 * GM/T 0018-2012 §6.3.14/6.3.17.
 * <p>
 * Note: {@code unsigned long} fields use Java {@code long} (8 bytes),
 * matching 64-bit Linux/macOS. On 64-bit Windows, {@code unsigned long}
 * is 4 bytes — use a platform-specific subclass if Windows support is needed.
 */
@Structure.FieldOrder({"ulAsymmAlgID", "ulSymmAlgID", "ECCCipherBlob", "PubKey", "cbEncryptedKey"})
public class ENVELOPEDKEYBLOB extends Structure {

    public long ulAsymmAlgID;
    public long ulSymmAlgID;
    public ECCCipher.ByValue ECCCipherBlob;
    public ECCrefPublicKey.ByValue PubKey;
    public byte[] cbEncryptedKey = new byte[64];

    public ENVELOPEDKEYBLOB() {
        super();
    }

    public static class ByReference extends ENVELOPEDKEYBLOB implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ulAsymmAlgID", "ulSymmAlgID", "ECCCipherBlob", "PubKey", "cbEncryptedKey");
    }
}
