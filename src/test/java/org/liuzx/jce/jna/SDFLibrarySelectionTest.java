package org.liuzx.jce.jna;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.liuzx.jce.provider.SDFConfig;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SDFLibrarySelectionTest {

    @TempDir
    Path temporaryDirectory;

    @AfterEach
    public void clearProperties() {
        System.clearProperty(SDFConfig.LIBRARY_PATH_PROPERTY);
        System.clearProperty(SDFConfig.PROFILE_PATH_PROPERTY);
        System.clearProperty(SDFConfig.LIBRARY_FALLBACK_ENABLED_PROPERTY);
    }

    @Test
    public void explicitPathFailureNeverAttemptsShortNameFallback() throws IOException {
        Path explicitLibrary = Files.createTempFile(temporaryDirectory, "vendor-sdf-", ".so");
        System.setProperty(SDFConfig.LIBRARY_PATH_PROPERTY, explicitLibrary.toString());
        System.setProperty(SDFConfig.LIBRARY_FALLBACK_ENABLED_PROPERTY, "true");
        List<String> loadAttempts = new ArrayList<String>();

        assertThrows(RuntimeException.class,
                () -> SDFLibraryLoader.loadLibrary(SDFConfig.getInstance(), path -> {
                    loadAttempts.add(path);
                    throw new UnsatisfiedLinkError("test load failure");
                }));

        assertEquals(1, loadAttempts.size());
        assertEquals(explicitLibrary.toRealPath().toString(), loadAttempts.get(0));
    }

    @Test
    public void fallbackRequiresOptInAndNoExplicitPath() throws IOException {
        configureExternalProfile();
        System.setProperty(SDFConfig.LIBRARY_FALLBACK_ENABLED_PROPERTY, "true");
        List<String> loadAttempts = new ArrayList<String>();
        SDFLibrary fallbackLibrary = dummyLibrary();

        SDFLibrary selected = SDFLibraryLoader.loadLibrary(SDFConfig.getInstance(), path -> {
            loadAttempts.add(path);
            if ("sdcrypto4j".equals(path)) {
                return fallbackLibrary;
            }
            throw new UnsatisfiedLinkError("test configured-path failure");
        });

        assertSame(fallbackLibrary, selected);
        assertEquals(2, loadAttempts.size());
        assertEquals("sdcrypto4j", loadAttempts.get(1));
    }

    @Test
    public void configuredPathFailureDoesNotFallbackByDefault() throws IOException {
        configureExternalProfile();
        List<String> loadAttempts = new ArrayList<String>();

        assertThrows(RuntimeException.class,
                () -> SDFLibraryLoader.loadLibrary(SDFConfig.getInstance(), path -> {
                    loadAttempts.add(path);
                    throw new UnsatisfiedLinkError("test load failure");
                }));

        assertEquals(1, loadAttempts.size());
    }

    private void configureExternalProfile() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "configured-sdf-", ".so");
        SDFConfig config = SDFConfig.getInstance();
        String json = "{\"defaultVendor\":\"Test\",\"vendors\":{\"Test\":{\"platforms\":{\""
                + config.getCurrentOs() + "\":{\"" + config.getCurrentArch() + "\":\""
                + library.toString().replace("\\", "\\\\") + "\"}}}}}";
        Path profile = Files.createTempFile(temporaryDirectory, "sdf-profile-", ".json");
        Files.write(profile, json.getBytes(StandardCharsets.UTF_8));
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());
    }

    private static SDFLibrary dummyLibrary() {
        return (SDFLibrary) Proxy.newProxyInstance(
                SDFLibrary.class.getClassLoader(),
                new Class<?>[]{SDFLibrary.class},
                (proxy, method, args) -> method.getReturnType() == Integer.TYPE ? 0 : null);
    }
}
