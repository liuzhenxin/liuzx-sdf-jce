package org.liuzx.jce.provider;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collections;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

public class SDFConfigTest {

    @TempDir
    Path temporaryDirectory;

    @AfterEach
    public void clearProperties() {
        System.clearProperty("liuzx.sdf.vendor");
        System.clearProperty(SDFConfig.LIBRARY_PATH_PROPERTY);
        System.clearProperty(SDFConfig.PROFILE_PATH_PROPERTY);
        System.clearProperty(SDFConfig.LIBRARY_FALLBACK_ENABLED_PROPERTY);
        System.clearProperty(SDFConfig.VENDOR_CONFIG_PATH_PROPERTY);
        System.clearProperty(SDFConfig.RSA_KEY_LAYOUT_PROPERTY);
        System.clearProperty(SDFConfig.CONFIG_PATH_PROPERTY);
    }

    @Test
    public void getDefaultVendorUsesSystemPropertyOverride() {
        System.setProperty("liuzx.sdf.vendor", "Shudun");

        assertEquals("Shudun", SDFConfig.getInstance().getDefaultVendor());
    }

    @Test
    public void getLibraryPathAcceptsExistingReadableAbsoluteOverride() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "libsdf-", ".so");
        System.setProperty(SDFConfig.LIBRARY_PATH_PROPERTY, library.toString());

        assertEquals(library.toRealPath().toString(),
                SDFConfig.getInstance().getDefaultLibraryPath());
    }

    @Test
    public void getLibraryPathRejectsRelativeOverride() {
        System.setProperty(SDFConfig.LIBRARY_PATH_PROPERTY, "relative/libsdhsmcrypto.so");

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> SDFConfig.getInstance().getDefaultLibraryPath());

        assertTrue(error.getMessage().contains("must be an absolute filesystem path"));
    }

    @Test
    public void getLibraryPathRejectsClasspathOverride() {
        System.setProperty(SDFConfig.LIBRARY_PATH_PROPERTY,
                "classpath:native/shudun/linux-x86_64/libsdhsmcrypto.so");

        assertThrows(IllegalArgumentException.class,
                () -> SDFConfig.getInstance().getDefaultLibraryPath());
    }

    @Test
    public void getLibraryPathRejectsMissingAbsoluteOverride() {
        Path missingLibrary = temporaryDirectory.resolve("missing-libsdf.so").toAbsolutePath();
        System.setProperty(SDFConfig.LIBRARY_PATH_PROPERTY, missingLibrary.toString());

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> SDFConfig.getInstance().getDefaultLibraryPath());

        assertTrue(error.getMessage().contains("does not exist"));
    }

    @Test
    public void getLibraryPathRejectsUnreadableAbsoluteOverride() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "unreadable-libsdf-", ".so");
        Set<PosixFilePermission> originalPermissions = Files.getPosixFilePermissions(library);
        try {
            Files.setPosixFilePermissions(library, Collections.<PosixFilePermission>emptySet());
            assumeFalse(Files.isReadable(library), "filesystem still reports a mode-000 file as readable");
            System.setProperty(SDFConfig.LIBRARY_PATH_PROPERTY, library.toString());

            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> SDFConfig.getInstance().getDefaultLibraryPath());

            assertTrue(error.getMessage().contains("is not readable"));
        } finally {
            Files.setPosixFilePermissions(library, originalPermissions);
        }
    }

    @Test
    public void shortNameFallbackIsDisabledByDefault() {
        assertFalse(SDFConfig.getInstance().isLibraryFallbackEnabled());
    }

    @Test
    public void shortNameFallbackRequiresOptInWithoutExplicitPath() {
        System.setProperty(SDFConfig.LIBRARY_FALLBACK_ENABLED_PROPERTY, "true");

        assertTrue(SDFConfig.getInstance().isLibraryFallbackEnabled());
    }

    @Test
    public void explicitPathDisablesShortNameFallbackEvenWhenOptedIn() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "libsdf-", ".so");
        System.setProperty(SDFConfig.LIBRARY_PATH_PROPERTY, library.toString());
        System.setProperty(SDFConfig.LIBRARY_FALLBACK_ENABLED_PROPERTY, "true");

        assertTrue(SDFConfig.getInstance().hasExplicitLibraryPath());
        assertFalse(SDFConfig.getInstance().isLibraryFallbackEnabled());
    }

    @Test
    public void getConfigPathAcceptsExistingReadableAbsoluteFile() throws IOException {
        Path config = Files.createTempFile(temporaryDirectory, "vendor-", ".ini");
        System.setProperty(SDFConfig.CONFIG_PATH_PROPERTY, config.toString());

        assertEquals(config.toRealPath().toString(), SDFConfig.getInstance().getConfigPath());
    }

    @Test
    public void getConfigPathRejectsRelativeFile() {
        System.setProperty(SDFConfig.CONFIG_PATH_PROPERTY, "conf/vendor.ini");

        assertThrows(IllegalArgumentException.class, () -> SDFConfig.getInstance().getConfigPath());
    }

    @Test
    public void externalProfileOverridesBundledProfile() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "external-sdf-", ".so");
        Path profile = writeProfile("External", library.toString());
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        assertEquals("External", SDFConfig.getInstance().getDefaultVendor());
        assertEquals(library.toRealPath().toString(), SDFConfig.getInstance().getDefaultLibraryPath());
    }

    @Test
    public void explicitLibraryPathBypassesInvalidExternalProfile() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "explicit-sdf-", ".so");
        System.setProperty(SDFConfig.LIBRARY_PATH_PROPERTY, library.toString());
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY,
                temporaryDirectory.resolve("missing-profile.json").toString());

        assertEquals(library.toRealPath().toString(), SDFConfig.getInstance().getDefaultLibraryPath());
    }

    @Test
    public void externalProfileRejectsRelativeLibraryPath() throws IOException {
        Path profile = writeProfile("External", "relative/libsdf.so");
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> SDFConfig.getInstance().getDefaultLibraryPath());

        assertTrue(error.getMessage().contains("absolute filesystem path"));
    }

    @Test
    public void externalProfileRejectsMissingSelectedLibrary() throws IOException {
        Path missingLibrary = temporaryDirectory.resolve("missing-vendor-library.so").toAbsolutePath();
        Path profile = writeProfile("External", missingLibrary.toString());
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> SDFConfig.getInstance().getDefaultLibraryPath());

        assertTrue(error.getMessage().contains("does not exist"));
    }

    @Test
    public void externalProfileRejectsUnknownDefaultVendor() throws IOException {
        String json = "{\"defaultVendor\":\"Missing\",\"vendors\":{\"Present\":{\"platforms\":{}}}}";
        Path profile = temporaryDirectory.resolve("invalid-profile.json");
        Files.write(profile, json.getBytes(StandardCharsets.UTF_8));
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> SDFConfig.getInstance().getDefaultVendor());

        assertTrue(error.getMessage().contains("is not present in 'vendors'"));
    }

    @Test
    public void classpathLibraryIsHashCheckedAndCached() throws IOException {
        String resource = "classpath:native/shudun/linux-x86_64/libsdhsmcrypto.so";
        String hash = "cfca94c2fe127051f0335da5c88f2bdef750276f0b68f15feec6d8b544e355a6";
        Path profile = writeObjectProfile("Classpath", resource, hash);
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        String first = SDFConfig.getInstance().getDefaultLibraryPath();
        String second = SDFConfig.getInstance().getDefaultLibraryPath();

        assertEquals(first, second);
        assertTrue(Files.isRegularFile(Paths.get(first)));
    }

    @Test
    public void classpathLibraryRejectsHashMismatch() throws IOException {
        Path profile = writeObjectProfile("Classpath",
                "classpath:native/shudun/linux-x86_64/libsdhsmcrypto.so",
                "0000000000000000000000000000000000000000000000000000000000000000");
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        assertThrows(SecurityException.class, () -> SDFConfig.getInstance().getDefaultLibraryPath());
    }

    @Test
    public void externalLibrarySupportsSha256Verification() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "verified-sdf-", ".so");
        Path profile = writeObjectProfile("Verified", library.toString(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        assertEquals(library.toRealPath().toString(), SDFConfig.getInstance().getDefaultLibraryPath());
    }

    @Test
    public void externalLibraryRejectsSha256Mismatch() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "verified-sdf-", ".so");
        Path profile = writeObjectProfile("Verified", library.toString(),
                "0000000000000000000000000000000000000000000000000000000000000000");
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        assertThrows(SecurityException.class, () -> SDFConfig.getInstance().getDefaultLibraryPath());
    }

    @Test
    public void vendorConfigPropertyTakesPrecedenceOverLegacyProperty() throws IOException {
        Path legacy = Files.createTempFile(temporaryDirectory, "legacy-", ".ini");
        Path preferred = Files.createTempFile(temporaryDirectory, "preferred-", ".ini");
        System.setProperty(SDFConfig.CONFIG_PATH_PROPERTY, legacy.toString());
        System.setProperty(SDFConfig.VENDOR_CONFIG_PATH_PROPERTY, preferred.toString());

        assertEquals(preferred.toRealPath().toString(), SDFConfig.getInstance().getConfigPath());
    }

    @Test
    public void rsaKeyLayoutCanBeOverriddenBySystemProperty() {
        System.setProperty(SDFConfig.RSA_KEY_LAYOUT_PROPERTY, "packed");

        assertEquals(SDFConfig.RsaKeyLayout.PACKED, SDFConfig.getInstance().getRsaKeyLayout());
    }

    @Test
    public void rsaKeyLayoutRejectsUnknownValue() {
        System.setProperty(SDFConfig.RSA_KEY_LAYOUT_PROPERTY, "vendor-magic");

        assertThrows(IllegalArgumentException.class, () -> SDFConfig.getInstance().getRsaKeyLayout());
    }

    @Test
    public void externalProfileSelectsPackedRsaLayout() throws IOException {
        Path library = Files.createTempFile(temporaryDirectory, "packed-sdf-", ".so");
        Path profile = writeObjectProfile("Packed", library.toString(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "packed");
        System.setProperty(SDFConfig.PROFILE_PATH_PROPERTY, profile.toString());

        assertEquals(SDFConfig.RsaKeyLayout.PACKED, SDFConfig.getInstance().getRsaKeyLayout());
    }

    private Path writeProfile(String vendor, String libraryPath) throws IOException {
        String json = "{\"defaultVendor\":" + jsonString(vendor)
                + ",\"vendors\":{" + jsonString(vendor)
                + ":{\"platforms\":{" + jsonString(SDFConfig.getInstance().getCurrentOs())
                + ":{" + jsonString(SDFConfig.getInstance().getCurrentArch())
                + ":" + jsonString(libraryPath) + "}}}}}";
        Path profile = Files.createTempFile(temporaryDirectory, "sdf-profile-", ".json");
        Files.write(profile, json.getBytes(StandardCharsets.UTF_8));
        return profile;
    }

    private Path writeObjectProfile(String vendor, String libraryPath, String sha256) throws IOException {
        return writeObjectProfile(vendor, libraryPath, sha256, null);
    }

    private Path writeObjectProfile(String vendor, String libraryPath, String sha256, String rsaKeyLayout)
            throws IOException {
        String json = "{\"defaultVendor\":" + jsonString(vendor)
                + ",\"vendors\":{" + jsonString(vendor)
                + ":{\"platforms\":{" + jsonString(SDFConfig.getInstance().getCurrentOs())
                + ":{" + jsonString(SDFConfig.getInstance().getCurrentArch())
                + ":{\"path\":" + jsonString(libraryPath)
                + ",\"sha256\":" + jsonString(sha256)
                + (rsaKeyLayout == null ? "" : ",\"rsaKeyLayout\":" + jsonString(rsaKeyLayout))
                + "}}}}}}";
        Path profile = Files.createTempFile(temporaryDirectory, "sdf-profile-", ".json");
        Files.write(profile, json.getBytes(StandardCharsets.UTF_8));
        return profile;
    }

    private String jsonString(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
