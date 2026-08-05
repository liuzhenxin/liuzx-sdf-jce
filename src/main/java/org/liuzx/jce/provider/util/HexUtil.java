package org.liuzx.jce.provider.util;

/**
 * Utility methods for hexadecimal encoding/decoding.
 */
public final class HexUtil {

    private HexUtil() {
    }

    /**
     * Encode a byte array to an uppercase hexadecimal string.
     */
    public static String toHexString(byte[] bytes) {
        if (bytes == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
