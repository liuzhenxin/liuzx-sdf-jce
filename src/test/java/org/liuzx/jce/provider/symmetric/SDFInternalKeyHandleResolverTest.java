package org.liuzx.jce.provider.symmetric;

import com.sun.jna.Pointer;
import org.junit.jupiter.api.Test;
import org.liuzx.jce.jna.SDFLibrary;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SDFInternalKeyHandleResolverTest {

    @Test
    void usesGetSymmKeyHandleForDysx() {
        List<String> calls = new ArrayList<>();
        SDFLibrary sdf = recordingLibrary(calls);

        int result = SDFInternalKeyHandleResolver.resolve(sdf, Pointer.NULL, 1, 16,
                new Pointer[1], "Dysx");

        assertEquals(0, result);
        assertEquals(Collections.singletonList("SDF_GetSymmKeyHandle"), calls);
    }

    @Test
    void keepsImportKekForOtherVendors() {
        List<String> calls = new ArrayList<>();
        SDFLibrary sdf = recordingLibrary(calls);

        int result = SDFInternalKeyHandleResolver.resolve(sdf, Pointer.NULL, 1, 16,
                new Pointer[1], "Shudun");

        assertEquals(0, result);
        assertEquals(Collections.singletonList("SDF_ImportKEK"), calls);
    }

    private static SDFLibrary recordingLibrary(List<String> calls) {
        return (SDFLibrary) Proxy.newProxyInstance(SDFLibrary.class.getClassLoader(),
                new Class<?>[] {SDFLibrary.class}, (proxy, method, args) -> {
                    calls.add(method.getName());
                    return 0;
                });
    }
}
