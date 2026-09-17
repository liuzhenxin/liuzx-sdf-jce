package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Opens an SDF device while tolerating vendor-specific entry points.
 *
 * <p>GM/T 0018-2012 only standardises {@link #OPEN_DEVICE}, which every vendor library
 * exports, so the standard call is tried first. Only when it fails and a vendor config
 * path was provided are the optional path-aware extensions probed
 * ({@code SDF_OpenDeviceWithPath} then {@code SDF_OpenDeviceEx}); JNA raises
 * {@link UnsatisfiedLinkError} when an invoked symbol is missing, which is treated as
 * "extension unavailable".</p>
 *
 * <p>DYSX also exposes the standard {@code SDF_OpenDevice} (reading its default config),
 * so no vendor is special-cased: the configured path is a fallback, not an override.</p>
 */
public final class SDFDeviceOpener {

    private static final LiuzxProviderLogger logger = LiuzxProviderLogger.getLogger(SDFDeviceOpener.class);

    static final String OPEN_DEVICE = "SDF_OpenDevice";
    static final String OPEN_DEVICE_EX = "SDF_OpenDeviceEx";
    static final String OPEN_DEVICE_WITH_PATH = "SDF_OpenDeviceWithPath";

    private static final Set<String> MISSING_SYMBOLS = ConcurrentHashMap.newKeySet();

    private static volatile String lastSuccessfulOperation = "uninitialized";

    private SDFDeviceOpener() {
    }

    /**
     * Returns the entry point that most recently opened a device successfully
     * ({@code SDF_OpenDeviceEx}, {@code SDF_OpenDeviceWithPath} or
     * {@code SDF_OpenDevice}), or {@code uninitialized} before the first open. Useful for
     * diagnostics and smoke tests that need to confirm the effective fallback path.
     */
    public static String getLastSuccessfulOperation() {
        return lastSuccessfulOperation;
    }

    /**
     * Opens the device using the richest entry point the loaded library supports.
     *
     * @param sdf JNA facade of the loaded library
     * @param phDeviceHandle receives the opened device handle
     * @param vendorConfigPath optional vendor config file or directory; {@code null} selects the
     *        standard call
     * @return the raw SDF return code, {@code 0} on success
     */
    public static int open(SDFLibrary sdf, Pointer[] phDeviceHandle, String vendorConfigPath) {
        // Standard entry point, available in every vendor library.
        int standardRv = sdf.SDF_OpenDevice(phDeviceHandle);
        if (standardRv == 0) {
            lastSuccessfulOperation = OPEN_DEVICE;
            return 0;
        }
        if (vendorConfigPath == null) {
            return standardRv;
        }
        int extensionRv = standardRv;
        if (isAvailable(OPEN_DEVICE_WITH_PATH)) {
            try {
                int rv = sdf.SDF_OpenDeviceWithPath(vendorConfigPath, phDeviceHandle);
                if (rv == 0) {
                    lastSuccessfulOperation = OPEN_DEVICE_WITH_PATH;
                    return 0;
                }
                logger.warn("{} failed (0x{}) for '{}'", OPEN_DEVICE_WITH_PATH, Integer.toHexString(rv),
                        vendorConfigPath);
                extensionRv = rv;
            } catch (UnsatisfiedLinkError missing) {
                markMissing(OPEN_DEVICE_WITH_PATH, missing);
            }
        }
        if (isAvailable(OPEN_DEVICE_EX)) {
            try {
                int rv = sdf.SDF_OpenDeviceEx(phDeviceHandle, vendorConfigPath, Pointer.NULL);
                if (rv == 0) {
                    lastSuccessfulOperation = OPEN_DEVICE_EX;
                    return 0;
                }
                logger.warn("{} failed (0x{}) for '{}'", OPEN_DEVICE_EX, Integer.toHexString(rv), vendorConfigPath);
                extensionRv = rv;
            } catch (UnsatisfiedLinkError missing) {
                markMissing(OPEN_DEVICE_EX, missing);
            }
        }
        return extensionRv;
    }

    private static boolean isAvailable(String symbol) {
        return !MISSING_SYMBOLS.contains(symbol);
    }

    private static void markMissing(String symbol, UnsatisfiedLinkError cause) {
        if (MISSING_SYMBOLS.add(symbol)) {
            logger.info("SDF library does not export {} ({}); ignoring optional extension", symbol,
                    cause.getMessage());
        }
    }

    /** Test hook: forget cached symbol availability. */
    static void resetCapabilities() {
        MISSING_SYMBOLS.clear();
        lastSuccessfulOperation = "uninitialized";
    }
}
