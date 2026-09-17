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
import java.util.List;
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
        SDFLibrary sdf = library(calls, Collections.<String>emptySet());

        int rv = SDFDeviceOpener.open(sdf, new Pointer[1], null);

        assertEquals(0, rv);
        assertEquals(Collections.singletonList("SDF_OpenDevice"), calls);
    }

    @Test
    void configPathUsesExtendedEntryPointWhenAvailable() {
        List<String> calls = new ArrayList<String>();
        SDFLibrary sdf = library(calls, Collections.<String>emptySet());

        int rv = SDFDeviceOpener.open(sdf, new Pointer[1], "/etc/hsm/vendor.ini");

        assertEquals(0, rv);
        assertEquals(Collections.singletonList("SDF_OpenDeviceEx"), calls);
    }

    @Test
    void missingExtendedEntryPointFallsBackToStandardAndCachesMiss() {
        List<String> calls = new ArrayList<String>();
        SDFLibrary sdf = library(calls,
                new java.util.HashSet<String>(Arrays.asList("SDF_OpenDeviceEx", "SDF_OpenDeviceWithPath")));

        assertEquals(0, SDFDeviceOpener.open(sdf, new Pointer[1], "/etc/hsm/vendor.ini"));
        assertEquals(0, SDFDeviceOpener.open(sdf, new Pointer[1], "/etc/hsm/vendor.ini"));

        // First call probes Ex and WithPath (both fail) then falls back; later calls skip the extensions.
        assertEquals(Arrays.asList("SDF_OpenDeviceEx", "SDF_OpenDeviceWithPath", "SDF_OpenDevice",
                "SDF_OpenDevice"), calls);
    }

    @Test
    void missingExtendedEntryPointFallsBackToWithPathWhenExported() {
        List<String> calls = new ArrayList<String>();
        SDFLibrary sdf = library(calls, Collections.singleton("SDF_OpenDeviceEx"));

        int rv = SDFDeviceOpener.open(sdf, new Pointer[1], "/etc/hsm/vendor.ini");

        assertEquals(0, rv);
        assertEquals(Arrays.asList("SDF_OpenDeviceEx", "SDF_OpenDeviceWithPath"), calls);
    }

    @Test
    void withPathReceivesConfigPathFirstAndHandleSecond() {
        final List<Object> captured = new ArrayList<Object>();
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
                    if ("SDF_OpenDeviceEx".equals(method.getName())) {
                        throw new UnsatisfiedLinkError("missing");
                    }
                    return 0;
                });

        Pointer[] handle = new Pointer[1];
        assertEquals(0, SDFDeviceOpener.open(sdf, handle, "/etc/shudun"));
        assertEquals(Arrays.asList("/etc/shudun", handle), captured);
    }

    @Test
    void withPathErrorFallsBackToStandardOpenDevice() {
        final List<String> calls = new ArrayList<String>();
        SDFLibrary sdf = (SDFLibrary) Proxy.newProxyInstance(SDFLibrary.class.getClassLoader(),
                new Class<?>[] {SDFLibrary.class}, (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method.getName(), args);
                    }
                    calls.add(method.getName());
                    if ("SDF_OpenDeviceEx".equals(method.getName())) {
                        throw new UnsatisfiedLinkError("missing");
                    }
                    if ("SDF_OpenDeviceWithPath".equals(method.getName())) {
                        return 0x01000112;
                    }
                    return 0;
                });

        int rv = SDFDeviceOpener.open(sdf, new Pointer[1], "/etc/hsm/vendor.ini");

        assertEquals(0, rv);
        assertEquals(Arrays.asList("SDF_OpenDeviceEx", "SDF_OpenDeviceWithPath", "SDF_OpenDevice"), calls);
    }

    @Test
    void extendedEntryPointErrorCodeIsPropagatedWithoutFallback() {
        final List<String> calls = new ArrayList<String>();
        SDFLibrary sdf = (SDFLibrary) Proxy.newProxyInstance(SDFLibrary.class.getClassLoader(),
                new Class<?>[] {SDFLibrary.class}, (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method.getName(), args);
                    }
                    calls.add(method.getName());
                    if ("SDF_OpenDeviceEx".equals(method.getName())) {
                        return 0x01000403;
                    }
                    return 0;
                });

        int rv = SDFDeviceOpener.open(sdf, new Pointer[1], "/etc/hsm/vendor.ini");

        assertEquals(0x01000403, rv);
        assertEquals(Collections.singletonList("SDF_OpenDeviceEx"), calls);
    }

    private static SDFLibrary library(final List<String> calls, final Set<String> missingSymbols) {
        return (SDFLibrary) Proxy.newProxyInstance(SDFLibrary.class.getClassLoader(),
                new Class<?>[] {SDFLibrary.class}, (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return objectMethod(proxy, method.getName(), args);
                    }
                    calls.add(method.getName());
                    if (missingSymbols.contains(method.getName())) {
                        throw new UnsatisfiedLinkError(
                                "Error looking up function '" + method.getName() + "'");
                    }
                    return 0;
                });
    }

    private static Object objectMethod(Object proxy, String name, Object[] args) {
        switch (name) {
            case "toString":
                return "SDFLibraryStub";
            case "hashCode":
                return System.identityHashCode(proxy);
            case "equals":
                return proxy == args[0];
            default:
                return null;
        }
    }
}
