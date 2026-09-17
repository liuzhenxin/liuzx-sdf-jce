package org.liuzx.jce.provider.symmetric;

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

class SDFInternalKeyHandleResolverTest {

    @BeforeEach
    @AfterEach
    void resetCapabilities() {
        SDFInternalKeyHandleResolver.resetCapabilities();
    }

    @Test
    void usesGetSymmKeyHandleWhenExported() {
        List<String> calls = new ArrayList<String>();

        int result = SDFInternalKeyHandleResolver.resolve(library(calls, Collections.<String>emptySet()),
                Pointer.NULL, 1, 16, new Pointer[1]);

        assertEquals(0, result);
        assertEquals(Collections.singletonList("SDF_GetSymmKeyHandle"), calls);
        assertEquals("SDF_GetSymmKeyHandle", SDFInternalKeyHandleResolver.operationName());
    }

    @Test
    void fallsBackToImportKekWhenGetSymmKeyHandleMissing() {
        List<String> calls = new ArrayList<String>();

        int result = SDFInternalKeyHandleResolver.resolve(library(calls, Collections.singleton("SDF_GetSymmKeyHandle")),
                Pointer.NULL, 1, 16, new Pointer[1]);

        assertEquals(0, result);
        assertEquals(Arrays.asList("SDF_GetSymmKeyHandle", "SDF_ImportKEK"), calls);
        assertEquals("SDF_ImportKEK", SDFInternalKeyHandleResolver.operationName());
    }

    @Test
    void cachesMissingGetSymmKeyHandleAfterFirstProbe() {
        List<String> calls = new ArrayList<String>();
        SDFLibrary sdf = library(calls, Collections.singleton("SDF_GetSymmKeyHandle"));

        SDFInternalKeyHandleResolver.resolve(sdf, Pointer.NULL, 1, 16, new Pointer[1]);
        SDFInternalKeyHandleResolver.resolve(sdf, Pointer.NULL, 1, 16, new Pointer[1]);

        assertEquals(Arrays.asList("SDF_GetSymmKeyHandle", "SDF_ImportKEK", "SDF_ImportKEK"), calls);
    }

    private static SDFLibrary library(final List<String> calls, final Set<String> missingSymbols) {
        return (SDFLibrary) Proxy.newProxyInstance(SDFLibrary.class.getClassLoader(),
                new Class<?>[] {SDFLibrary.class}, (proxy, method, args) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        if ("toString".equals(method.getName())) {
                            return "SDFLibraryStub";
                        }
                        if ("hashCode".equals(method.getName())) {
                            return System.identityHashCode(proxy);
                        }
                        if ("equals".equals(method.getName())) {
                            return proxy == args[0];
                        }
                        return null;
                    }
                    calls.add(method.getName());
                    if (missingSymbols.contains(method.getName())) {
                        throw new UnsatisfiedLinkError("Error looking up function '" + method.getName() + "'");
                    }
                    return 0;
                });
    }
}
