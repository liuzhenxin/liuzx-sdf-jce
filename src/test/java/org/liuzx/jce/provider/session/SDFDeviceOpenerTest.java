package org.liuzx.jce.provider.session;

import com.sun.jna.Pointer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.jna.SDFLibrary;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SDFDeviceOpenerTest {

    @BeforeEach
    @AfterEach
    void resetCapabilities() {
        SDFDeviceOpener.resetCapabilities();
    }

    @Test
    void nullConfigUsesStandardOpenDevice() {
        List<String> calls = new ArrayList<String>();

        int rv = SDFDeviceOpener.open(library(calls, empty(), emptyResults()), new Pointer[1], null);

        assertEquals(0, rv);
        assertEquals(Collections.singletonList("SDF_OpenDevice"), calls);
        assertEquals("SDF_OpenDevice", SDFDeviceOpener.getLastSuccessfulOperation());
    }

    @Test
    void standardOpenIsPreferredEvenWithConfigPath() {
        List<String> calls = new ArrayList<String>();

        int rv = SDFDeviceOpener.open(library(calls, empty(), emptyResults()), new Pointer[1], "/etc/hsm/vendor.ini");

        assertEquals(0, rv);
        assertEquals(Collections.singletonList("SDF_OpenDevice"), calls);
        assertEquals("SDF_OpenDevice", SDFDeviceOpener.getLastSuccessfulOperation());
    }

    @Test
    void standardFailureUsesWithPathWhenExported() {
        List<String> calls = new ArrayList<String>();
        Map<String, Integer> results = new HashMap<String, Integer>();
        results.put("SDF_OpenDevice", 0x01000112);

        int rv = SDFDeviceOpener.open(library(calls, empty(), results), new Pointer[1], "/etc/shudun");

        assertEquals(0, rv);
        assertEquals(Arrays.asList("SDF_OpenDevice", "SDF_OpenDeviceWithPath"), calls);
        assertEquals("SDF_OpenDeviceWithPath", SDFDeviceOpener.getLastSuccessfulOperation());
    }

    @Test
    void withPathReceivesConfigPathFirstAndHandleSecond() {
        final List<Object> captured = new ArrayList<Object>();
        final Map<String, Integer> results = new HashMap<String, Integer>();
        results.put("SDF_OpenDevice", 0x01000112);
        SDFLibrary sdf = (SDFLibrary) Proxy.newProxyInstance(SDFLibrary.class.getClassLoader(),
                new Class<?>[] {SDFLibrary.class}, (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method.getName(), args);
                    }
                    if ("SDF_OpenDeviceWithPath".equals(method.getName())) {
                        captured.add(args[0]);
                        captured.add(args[1]);
                        return 0;
                    }
                    return results.getOrDefault(method.getName(), 0);
                });

        Pointer[] handle = new Pointer[1];
        assertEquals(0, SDFDeviceOpener.open(sdf, handle, "/etc/shudun"));
        assertEquals(Arrays.asList("/etc/shudun", handle), captured);
    }

    @Test
    void standardAndWithPathFailureUsesExtendedEntryPoint() {
        List<String> calls = new ArrayList<String>();
        Map<String, Integer> results = new HashMap<String, Integer>();
        results.put("SDF_OpenDevice", 0x01000112);

        int rv = SDFDeviceOpener.open(library(calls, Collections.singleton("SDF_OpenDeviceWithPath"), results),
                new Pointer[1], "/etc/vendor/cacipher.ini");

        assertEquals(0, rv);
        assertEquals(Arrays.asList("SDF_OpenDevice", "SDF_OpenDeviceWithPath", "SDF_OpenDeviceEx"), calls);
        assertEquals("SDF_OpenDeviceEx", SDFDeviceOpener.getLastSuccessfulOperation());
    }

    @Test
    void missingExtensionsAreProbedOnceAndCached() {
        List<String> calls = new ArrayList<String>();
        Map<String, Integer> results = new HashMap<String, Integer>();
        results.put("SDF_OpenDevice", 0x01000112);
        SDFLibrary sdf = library(calls,
                new java.util.HashSet<String>(Arrays.asList("SDF_OpenDeviceWithPath", "SDF_OpenDeviceEx")), results);

        assertEquals(0x01000112, SDFDeviceOpener.open(sdf, new Pointer[1], "/etc/hsm/vendor.ini"));
        assertEquals(0x01000112, SDFDeviceOpener.open(sdf, new Pointer[1], "/etc/hsm/vendor.ini"));

        assertEquals(Arrays.asList("SDF_OpenDevice", "SDF_OpenDeviceWithPath", "SDF_OpenDeviceEx",
                "SDF_OpenDevice"), calls);
    }

    @Test
    void extensionErrorCodeIsReturnedWhenEveryAttemptFails() {
        List<String> calls = new ArrayList<String>();
        Map<String, Integer> results = new HashMap<String, Integer>();
        results.put("SDF_OpenDevice", 0x01000112);
        results.put("SDF_OpenDeviceWithPath", 0x01000113);

        int rv = SDFDeviceOpener.open(library(calls, Collections.singleton("SDF_OpenDeviceEx"), results),
                new Pointer[1], "/etc/hsm/vendor.ini");

        assertEquals(0x01000113, rv);
    }

    @Test
    void standardFailureWithoutConfigReturnsStandardError() {
        List<String> calls = new ArrayList<String>();
        Map<String, Integer> results = new HashMap<String, Integer>();
        results.put("SDF_OpenDevice", 0x01000112);

        int rv = SDFDeviceOpener.open(library(calls, empty(), results), new Pointer[1], null);

        assertEquals(0x01000112, rv);
        assertEquals(Collections.singletonList("SDF_OpenDevice"), calls);
    }

    private static Map<String, Integer> emptyResults() {
        return Collections.emptyMap();
    }

    private static Set<String> empty() {
        return Collections.emptySet();
    }

    private static SDFLibrary library(final List<String> calls, final Set<String> missingSymbols,
            final Map<String, Integer> results) {
        return (SDFLibrary) Proxy.newProxyInstance(SDFLibrary.class.getClassLoader(),
                new Class<?>[] {SDFLibrary.class}, (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method.getName(), args);
                    }
                    calls.add(method.getName());
                    if (missingSymbols.contains(method.getName())) {
                        throw new UnsatisfiedLinkError("Error looking up function '" + method.getName() + "'");
                    }
                    return results.getOrDefault(method.getName(), 0);
                });
    }

    private static Object objectMethod(Object proxy, String name, Object[] args) {
        if ("toString".equals(name)) {
            return "SDFLibraryStub";
        }
        if ("hashCode".equals(name)) {
            return System.identityHashCode(proxy);
        }
        if ("equals".equals(name)) {
            return proxy == args[0];
        }
        return null;
    }
}
