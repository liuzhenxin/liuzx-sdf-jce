package org.liuzx.jce.provider.symmetric;

public final class SDFSM4Keys {

    private SDFSM4Keys() {
    }

    public static SDFSM4InternalKey internalKey(int keyIndex) {
        return new SDFSM4InternalKey(keyIndex);
    }

    public static SDFSM4InternalKey internalKey(int keyIndex, byte[] encryptedKey) {
        return new SDFSM4InternalKey(keyIndex, encryptedKey);
    }
}
