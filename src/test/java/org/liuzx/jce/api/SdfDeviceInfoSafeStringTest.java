package org.liuzx.jce.api;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 校验 {@link SdfDeviceInfo} 不泄漏设备序列号，不依赖任何硬件。
 */
class SdfDeviceInfoSafeStringTest {

    private static final String SERIAL_MARKER = "SN-LEAK-TEST-0001";

    @Test
    void hasNoSerialAccessor() {
        for (Method method : SdfDeviceInfo.class.getDeclaredMethods()) {
            String name = method.getName().toLowerCase();
            assertFalse(name.contains("serial"),
                    "SdfDeviceInfo must not expose a serial accessor: " + method.getName());
        }
    }

    @Test
    void safeStringDoesNotContainSerialOrPaths() {
        SdfDeviceInfo info = new SdfDeviceInfo(
                "LiuZX Test Vendor",
                "TestDevice",
                "ModelClass-X",
                1, 2, 0x00004000, 0x00000002, 4096,
                "abcdef0123456789");
        String safe = info.toSafeString();
        assertTrue(safe.contains("LiuZX Test Vendor"));
        assertTrue(safe.contains("ModelClass-X"));
        assertFalse(safe.toLowerCase().contains("serial"), "toSafeString must not mention serial");
        assertFalse(safe.contains(SERIAL_MARKER), "toSafeString must not contain a serial value");
        assertFalse(safe.contains("/"), "toSafeString must not contain filesystem paths");
        assertFalse(safe.contains(".so"), "toSafeString must not contain library file names");
        assertFalse(safe.contains(".ini"), "toSafeString must not contain config file names");
    }

    @Test
    void toStringMatchesSafeString() {
        SdfDeviceInfo info = new SdfDeviceInfo(
                "V", "D", "M", 1, 1, 0, 0, 0, "digest");
        assertFalse(info.toString().contains(SERIAL_MARKER));
        assertTrue(info.toString().contains("modelClass=M"));
    }

    @Test
    void fieldSetContainsNoSerialNamedComponent() {
        Set<String> methodNames = new HashSet<String>();
        for (Method method : SdfDeviceInfo.class.getDeclaredMethods()) {
            methodNames.add(method.getName());
        }
        assertFalse(methodNames.contains("deviceSerial"), "unexpected deviceSerial accessor");
        assertFalse(methodNames.contains("getDeviceSerial"), "unexpected getDeviceSerial accessor");
        assertTrue(methodNames.containsAll(Arrays.asList(
                "issuerName", "deviceName", "deviceModelClass", "libraryDigestPrefix")));
    }
}
