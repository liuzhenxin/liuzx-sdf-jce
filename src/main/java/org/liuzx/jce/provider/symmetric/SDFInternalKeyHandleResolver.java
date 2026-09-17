package org.liuzx.jce.provider.symmetric;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves a hardware-internal symmetric key index to a session key handle.
 *
 * <p>There is no single GM/T 0018 call for this: {@code SDF_GetSymmKeyHandle} is the
 * common extension exported by DYSX and SanSec, while Shudun only exports
 * {@code SDF_ImportKEK}. The capability is therefore probed at runtime instead of being
 * selected by vendor name, so adding a vendor does not require code changes.</p>
 */
public final class SDFInternalKeyHandleResolver {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(SDFInternalKeyHandleResolver.class);

    static final String GET_SYMM_KEY_HANDLE = "SDF_GetSymmKeyHandle";
    static final String IMPORT_KEK = "SDF_ImportKEK";

    private static final Set<String> MISSING_SYMBOLS = ConcurrentHashMap.newKeySet();

    private SDFInternalKeyHandleResolver() {
    }

    /**
     * Imports the internal key {@code keyIndex} into a session key handle, preferring
     * {@code SDF_GetSymmKeyHandle} and falling back to {@code SDF_ImportKEK}.
     */
    public static int resolve(SDFLibrary sdf, Pointer sessionHandle, int keyIndex, int keyLengthBytes,
            Pointer[] keyHandle) {
        if (!MISSING_SYMBOLS.contains(GET_SYMM_KEY_HANDLE)) {
            try {
                return sdf.SDF_GetSymmKeyHandle(sessionHandle, keyIndex, keyHandle);
            } catch (UnsatisfiedLinkError missing) {
                if (MISSING_SYMBOLS.add(GET_SYMM_KEY_HANDLE)) {
                    logger.info("SDF library does not export {} ({}); using {} instead",
                            GET_SYMM_KEY_HANDLE, missing.getMessage(), IMPORT_KEK);
                }
            }
        }
        return sdf.SDF_ImportKEK(sessionHandle, keyIndex, keyLengthBytes, keyHandle);
    }

    /**
     * Name of the function used by the most recent {@link #resolve} attempt, for error
     * messages.
     */
    public static String operationName() {
        return MISSING_SYMBOLS.contains(GET_SYMM_KEY_HANDLE) ? IMPORT_KEK : GET_SYMM_KEY_HANDLE;
    }

    /** Test hook: forget cached symbol availability. */
    static void resetCapabilities() {
        MISSING_SYMBOLS.clear();
    }
}
