package org.liuzx.jce.jna;

import com.sun.jna.Native;
import org.liuzx.jce.provider.SDFConfig;

/**
 * Native-library selection policy kept separate from the JNA interface so it can be
 * tested without loading a real vendor library.
 */
final class SDFLibraryLoader {

    private static final String FALLBACK_LIBRARY_NAME = "sdcrypto4j";

    interface NativeLoader {
        SDFLibrary load(String path);
    }

    private SDFLibraryLoader() {
    }

    static SDFLibrary loadLibrary() {
        return loadLibrary(SDFConfig.getInstance(), path -> Native.load(path, SDFLibrary.class));
    }

    static SDFLibrary loadLibrary(SDFConfig config, NativeLoader loader) {
        String path = config.getDefaultLibraryPath();
        try {
            return loader.load(path);
        } catch (Throwable firstError) {
            System.err.println("[SDFLibrary] Failed to load native library with path: " + path);
            System.err.println("[SDFLibrary] Error: " + firstError);
            if (firstError.getCause() != null) {
                System.err.println("[SDFLibrary] Caused by: " + firstError.getCause());
            }
            if (!config.isLibraryFallbackEnabled()) {
                String reason = config.hasExplicitLibraryPath()
                        ? "an explicit library path is authoritative"
                        : "short-name fallback is disabled; set '"
                                + SDFConfig.LIBRARY_FALLBACK_ENABLED_PROPERTY + "=true' to enable it";
                throw new RuntimeException(
                        "Failed to load SDF native library. Path='" + path + "' and " + reason
                                + ". java.library.path='" + System.getProperty("java.library.path")
                                + "', jna.library.path='" + System.getProperty("jna.library.path")
                                + "'. Error: " + firstError,
                        firstError);
            }
            try {
                System.err.println("[SDFLibrary] Trying fallback: Native.load(\"" + FALLBACK_LIBRARY_NAME
                        + "\", ...)");
                SDFLibrary library = loader.load(FALLBACK_LIBRARY_NAME);
                System.err.println("[SDFLibrary] Fallback succeeded via short name");
                return library;
            } catch (Throwable fallbackError) {
                System.err.println("[SDFLibrary] Fallback also failed: " + fallbackError);
                throw new RuntimeException(
                        "Failed to load SDF native library. Path='" + path
                                + "', java.library.path='" + System.getProperty("java.library.path")
                                + "', jna.library.path='" + System.getProperty("jna.library.path")
                                + "'. First error: " + firstError
                                + ". Fallback error: " + fallbackError,
                        firstError);
            }
        }
    }
}
