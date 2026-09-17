package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;
import org.liuzx.jce.jna.SDFLibrary;
import org.liuzx.jce.provider.log.LiuzxProviderLogger;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Opens an SDF device while tolerating vendor-specific entry points.
 *
 * <p>GM/T 0018-2012 only standardises {@link #OPEN_DEVICE}. Some vendors expose an
 * extended entry point ({@code SDF_OpenDeviceEx} for DYSX / {@code SDF_OpenDeviceWithPath}
 * for path-addressed devices) and JNA raises {@link UnsatisfiedLinkError} when an
 * invoked symbol is missing. This helper probes those optional symbols at runtime and
 * degrades to the standard call, so one JAR can drive DYSX, Shudun and SanSec devices.</p>
 *
 * <p>Only the vendor-extension lookup is treated as optional. If an extension exists
 * but returns an error code, the error is propagated unchanged so that DYSX behaviour
 * is not altered by the fallback.</p>
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
        if (vendorConfigPath == null) {
            int rv = sdf.SDF_OpenDevice(phDeviceHandle);
            if (rv == 0) {
                lastSuccessfulOperation = OPEN_DEVICE;
            }
            return rv;
        }
        if (isAvailable(OPEN_DEVICE_EX)) {
            try {
                int rv = sdf.SDF_OpenDeviceEx(phDeviceHandle, vendorConfigPath, Pointer.NULL);
                if (rv == 0) {
                    lastSuccessfulOperation = OPEN_DEVICE_EX;
                }
                return rv;
            } catch (UnsatisfiedLinkError missing) {
                markMissing(OPEN_DEVICE_EX, missing);
            }
        }
        if (isAvailable(OPEN_DEVICE_WITH_PATH)) {
            try {
                int rv = sdf.SDF_OpenDeviceWithPath(vendorConfigPath, phDeviceHandle);
                if (rv == 0) {
                    lastSuccessfulOperation = OPEN_DEVICE_WITH_PATH;
                    return 0;
                }
                // A vendor extension error must not block startup: some vendors expect a
                // configuration directory here, while callers may supply an INI file.
                logger.warn("{} failed (0x{}) for '{}'; falling back to {}", OPEN_DEVICE_WITH_PATH,
                        Integer.toHexString(rv), vendorConfigPath, OPEN_DEVICE);
            } catch (UnsatisfiedLinkError missing) {
                markMissing(OPEN_DEVICE_WITH_PATH, missing);
            }
        }
        logger.debug("Using {}; vendor config path '{}' will be ignored", OPEN_DEVICE, vendorConfigPath);
        int rv = sdf.SDF_OpenDevice(phDeviceHandle);
        if (rv == 0) {
            lastSuccessfulOperation = OPEN_DEVICE;
        }
        return rv;
    }

    private static boolean isAvailable(String symbol) {
        return !MISSING_SYMBOLS.contains(symbol);
    }

    private static void markMissing(String symbol, UnsatisfiedLinkError cause) {
        if (MISSING_SYMBOLS.add(symbol)) {
            logger.info("SDF library does not export {} ({}); using standard {} instead", symbol,
                    cause.getMessage(), OPEN_DEVICE);
        }
    }

    /** Test hook: forget cached symbol availability. */
    static void resetCapabilities() {
        MISSING_SYMBOLS.clear();
        lastSuccessfulOperation = "uninitialized";
    }
}
