package org.liuzx.jce.provider.symmetric;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.SDFConfig;

/** Resolves a hardware-internal symmetric key index to a session key handle. */
public final class SDFInternalKeyHandleResolver {

    private static final String DYSX_VENDOR = "Dysx";

    private SDFInternalKeyHandleResolver() {
    }

    public static int resolve(SDFLibrary sdf, Pointer sessionHandle, int keyIndex, int keyLengthBytes,
            Pointer[] keyHandle) {
        return resolve(sdf, sessionHandle, keyIndex, keyLengthBytes, keyHandle,
                SDFConfig.getInstance().getDefaultVendor());
    }

    static int resolve(SDFLibrary sdf, Pointer sessionHandle, int keyIndex, int keyLengthBytes,
            Pointer[] keyHandle, String vendor) {
        if (DYSX_VENDOR.equalsIgnoreCase(vendor)) {
            return sdf.SDF_GetSymmKeyHandle(sessionHandle, keyIndex, keyHandle);
        }
        return sdf.SDF_ImportKEK(sessionHandle, keyIndex, keyLengthBytes, keyHandle);
    }

    public static String operationName() {
        return DYSX_VENDOR.equalsIgnoreCase(SDFConfig.getInstance().getDefaultVendor())
                ? "SDF_GetSymmKeyHandle" : "SDF_ImportKEK";
    }
}
