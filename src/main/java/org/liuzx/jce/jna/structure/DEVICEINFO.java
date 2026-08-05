package org.liuzx.jce.jna.structure;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

/**
 * SDF Device Information structure (DEVICEINFO).
 * GM/T 0018-2012 §6.2.
 */
@Structure.FieldOrder({"IssuerName", "DeviceName", "DeviceSerial", "DeviceVersion",
        "StandardVersion", "AsymAlgAbility", "SymAlgAbility", "HashAlgAbility", "BufferSize"})
public class DEVICEINFO extends Structure {

    public byte[] IssuerName = new byte[40];
    public byte[] DeviceName = new byte[16];
    public byte[] DeviceSerial = new byte[16];
    public int DeviceVersion;
    public int StandardVersion;
    public int[] AsymAlgAbility = new int[2];
    public int SymAlgAbility;
    public int HashAlgAbility;
    public int BufferSize;

    public DEVICEINFO() {
        super();
    }

    public static class ByReference extends DEVICEINFO implements Structure.ByReference {
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("IssuerName", "DeviceName", "DeviceSerial", "DeviceVersion",
                "StandardVersion", "AsymAlgAbility", "SymAlgAbility", "HashAlgAbility", "BufferSize");
    }
}
