package org.liuzx.jce.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SDFConfigTest {

    @AfterEach
    public void clearProperties() {
        System.clearProperty("liuzx.sdf.vendor");
        System.clearProperty("liuzx.sdf.library.path");
    }

    @Test
    public void getDefaultVendorUsesSystemPropertyOverride() {
        System.setProperty("liuzx.sdf.vendor", "Shudun");

        assertEquals("Shudun", SDFConfig.getInstance().getDefaultVendor());
    }

    @Test
    public void getLibraryPathUsesExplicitPathOverride() {
        System.setProperty("liuzx.sdf.library.path", "relative/libsdhsmcrypto.so");

        String expected = Paths.get(System.getProperty("user.dir"), "relative/libsdhsmcrypto.so").normalize().toString();

        assertEquals(expected, SDFConfig.getInstance().getDefaultLibraryPath());
    }

    @Test
    public void getLibraryPathExtractsClasspathNativeLibrary() {
        System.setProperty("liuzx.sdf.library.path", "classpath:native/shudun/linux-x86_64/libsdhsmcrypto.so");

        String libraryPath = SDFConfig.getInstance().getDefaultLibraryPath();
        Path extractedPath = Paths.get(libraryPath);

        assertTrue(Files.isRegularFile(extractedPath));
        assertEquals("libsdhsmcrypto.so", extractedPath.getFileName().toString());
    }
}
