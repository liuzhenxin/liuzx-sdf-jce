package org.liuzx.jce.provider;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves the SDF native library from an explicit path, an external profile, or
 * the profile bundled in this JAR (in that order).
 */
public class SDFConfig {

    private static final String CONFIG_RESOURCE = "/sdf-config.json";
    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final String SHA_256_PATTERN = "[0-9a-fA-F]{64}";

    public static final String VENDOR_PROPERTY = "liuzx.sdf.vendor";
    public static final String LIBRARY_PATH_PROPERTY = "liuzx.sdf.library.path";
    public static final String PROFILE_PATH_PROPERTY = "liuzx.sdf.profile.path";
    public static final String LIBRARY_FALLBACK_ENABLED_PROPERTY = "liuzx.sdf.library.fallback-enabled";
    public static final String VENDOR_CONFIG_PATH_PROPERTY = "liuzx.sdf.vendor-config.path";
    public static final String RSA_KEY_LAYOUT_PROPERTY = "liuzx.sdf.rsa-key-layout";

    /** @deprecated Use {@link #VENDOR_CONFIG_PATH_PROPERTY}. */
    @Deprecated
    public static final String CONFIG_PATH_PROPERTY = "liuzx.sdf.config.path";

    private static final SDFConfig INSTANCE = new SDFConfig();
    private static final Map<String, String> EXTRACTED_LIBRARIES = new ConcurrentHashMap<String, String>();
    private static final Object EXTRACTION_LOCK = new Object();

    private final ConfigData bundledConfig;
    private final String currentOs;
    private final String currentArch;

    private SDFConfig() {
        this.currentOs = detectOS();
        this.currentArch = detectArch();
        this.bundledConfig = loadBundledConfig();
    }

    public static SDFConfig getInstance() {
        return INSTANCE;
    }

    /** Explicit library paths are authoritative and bypass profile parsing. */
    public String getDefaultLibraryPath() {
        String overridePath = trimToNull(System.getProperty(LIBRARY_PATH_PROPERTY));
        if (overridePath != null) {
            return validateSystemPropertyFile(LIBRARY_PATH_PROPERTY, "SDF native library", overridePath);
        }

        ConfigData config = getActiveConfig();
        return resolveLibraryPath(config, resolveVendor(config));
    }

    public String getLibraryPath(String vendorName) {
        String overridePath = trimToNull(System.getProperty(LIBRARY_PATH_PROPERTY));
        if (overridePath != null) {
            return validateSystemPropertyFile(LIBRARY_PATH_PROPERTY, "SDF native library", overridePath);
        }
        return resolveLibraryPath(getActiveConfig(), requireText(vendorName, "vendor name"));
    }

    public String getDefaultVendor() {
        return resolveVendor(getActiveConfig());
    }

    public boolean hasExplicitLibraryPath() {
        return trimToNull(System.getProperty(LIBRARY_PATH_PROPERTY)) != null;
    }

    /** Short-name discovery is opt-in and cannot override an explicit path. */
    public boolean isLibraryFallbackEnabled() {
        return !hasExplicitLibraryPath()
                && Boolean.parseBoolean(trimToNull(System.getProperty(LIBRARY_FALLBACK_ENABLED_PROPERTY)));
    }

    /**
     * Returns the optional vendor INI file passed to SDF_OpenDeviceEx. The clearer
     * vendor-config property takes precedence over the legacy config property.
     */
    public String getConfigPath() {
        String path = trimToNull(System.getProperty(VENDOR_CONFIG_PATH_PROPERTY));
        String propertyName = VENDOR_CONFIG_PATH_PROPERTY;
        if (path == null) {
            path = trimToNull(System.getProperty(CONFIG_PATH_PROPERTY));
            propertyName = CONFIG_PATH_PROPERTY;
        }
        return path == null
                ? null
                : validateSystemPropertyFile(propertyName, "SDF vendor configuration", path);
    }

    public String getCurrentOs() {
        return currentOs;
    }

    public String getCurrentArch() {
        return currentArch;
    }

    /**
     * Returns the RSA structure ABI used by the selected vendor library. The SDF
     * standard uses fixed-size, right-aligned fields; PACKED supports vendor SDKs
     * that compact fields according to the requested key size.
     */
    public RsaKeyLayout getRsaKeyLayout() {
        String override = trimToNull(System.getProperty(RSA_KEY_LAYOUT_PROPERTY));
        if (override != null) {
            return RsaKeyLayout.parse(override, "system property '" + RSA_KEY_LAYOUT_PROPERTY + "'");
        }
        ConfigData config = getActiveConfig();
        return getLibrarySpec(config, resolveVendor(config)).rsaKeyLayout;
    }

    private ConfigData getActiveConfig() {
        String profilePath = trimToNull(System.getProperty(PROFILE_PATH_PROPERTY));
        if (profilePath == null) {
            return bundledConfig;
        }

        String realPath = validateSystemPropertyFile(PROFILE_PATH_PROPERTY, "SDF profile", profilePath);
        try (Reader reader = Files.newBufferedReader(Paths.get(realPath), StandardCharsets.UTF_8)) {
            return parseAndValidate(reader, "external profile '" + realPath + "'");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read SDF profile: " + realPath, e);
        }
    }

    private ConfigData loadBundledConfig() {
        try (InputStream stream = SDFConfig.class.getResourceAsStream(CONFIG_RESOURCE)) {
            if (stream == null) {
                throw new IllegalStateException("Cannot find bundled SDF profile: " + CONFIG_RESOURCE);
            }
            return parseAndValidate(new InputStreamReader(stream, StandardCharsets.UTF_8),
                    "bundled profile '" + CONFIG_RESOURCE + "'");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read bundled SDF profile: " + CONFIG_RESOURCE, e);
        }
    }

    private ConfigData parseAndValidate(Reader reader, String source) {
        final ConfigData config;
        try {
            config = new Gson().fromJson(reader, ConfigData.class);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Failed to parse " + source + ": " + e.getMessage(), e);
        }
        if (config == null) {
            throw new IllegalArgumentException(source + " must contain a JSON object");
        }

        config.defaultVendor = requireText(config.defaultVendor, source + " field 'defaultVendor'");
        if (config.vendors == null || config.vendors.isEmpty()) {
            throw new IllegalArgumentException(source + " field 'vendors' must not be empty");
        }
        if (!config.vendors.containsKey(config.defaultVendor)) {
            throw new IllegalArgumentException(source + " defaultVendor '" + config.defaultVendor
                    + "' is not present in 'vendors'");
        }

        for (Map.Entry<String, ConfigData.VendorEntry> vendor : config.vendors.entrySet()) {
            String vendorName = requireText(vendor.getKey(), source + " vendor name");
            ConfigData.VendorEntry vendorEntry = vendor.getValue();
            if (vendorEntry == null || vendorEntry.platforms == null || vendorEntry.platforms.isEmpty()) {
                throw new IllegalArgumentException(source + " vendor '" + vendorName
                        + "' must define a non-empty 'platforms' object");
            }
            for (Map.Entry<String, Map<String, JsonElement>> platform : vendorEntry.platforms.entrySet()) {
                String os = requireText(platform.getKey(), source + " OS name for vendor '" + vendorName + "'");
                Map<String, JsonElement> architectures = platform.getValue();
                if (architectures == null || architectures.isEmpty()) {
                    throw new IllegalArgumentException(source + " vendor '" + vendorName + "' OS '" + os
                            + "' must define at least one architecture");
                }
                for (Map.Entry<String, JsonElement> architecture : architectures.entrySet()) {
                    String arch = requireText(architecture.getKey(), source + " architecture for vendor '"
                            + vendorName + "' OS '" + os + "'");
                    LibrarySpec spec = parseLibrarySpec(architecture.getValue(), source + " vendor '"
                            + vendorName + "' platform '" + os + "/" + arch + "'");
                    validateConfiguredPathSyntax(spec.path, source + " vendor '" + vendorName
                            + "' platform '" + os + "/" + arch + "'");
                }
            }
        }
        return config;
    }

    private String resolveVendor(ConfigData config) {
        String override = trimToNull(System.getProperty(VENDOR_PROPERTY));
        return override == null ? config.defaultVendor : override;
    }

    private String resolveLibraryPath(ConfigData config, String vendorName) {
        LibrarySpec spec = getLibrarySpec(config, vendorName);
        if (spec.path.startsWith(CLASSPATH_PREFIX)) {
            return extractClasspathLibrary(spec);
        }
        return validateConfiguredLibraryFile(vendorName, spec);
    }

    private LibrarySpec getLibrarySpec(ConfigData config, String vendorName) {
        ConfigData.VendorEntry vendor = config.vendors.get(vendorName);
        if (vendor == null) {
            throw new IllegalStateException("No SDF configuration found for vendor: " + vendorName);
        }
        Map<String, JsonElement> architectures = vendor.platforms.get(currentOs);
        if (architectures == null) {
            throw new IllegalStateException("Unsupported OS '" + currentOs + "' for vendor: " + vendorName);
        }
        JsonElement configuredLibrary = architectures.get(currentArch);
        if (configuredLibrary == null) {
            throw new IllegalStateException("Unsupported architecture '" + currentArch + "' for OS '"
                    + currentOs + "' and vendor '" + vendorName + "'");
        }
        return parseLibrarySpec(configuredLibrary, "vendor '" + vendorName + "' platform '"
                + currentOs + "/" + currentArch + "'");
    }

    private LibrarySpec parseLibrarySpec(JsonElement element, String location) {
        if (element == null || element.isJsonNull()) {
            throw new IllegalArgumentException(location + " must define a library path");
        }
        if (element.isJsonPrimitive() && element.getAsJsonPrimitive().isString()) {
            return new LibrarySpec(requireText(element.getAsString(), location + " library path"), null,
                    RsaKeyLayout.STANDARD);
        }
        if (!element.isJsonObject()) {
            throw new IllegalArgumentException(location
                    + " must be a string or an object with 'path' and optional 'sha256'");
        }

        JsonObject object = element.getAsJsonObject();
        for (Map.Entry<String, JsonElement> field : object.entrySet()) {
            if (!"path".equals(field.getKey()) && !"sha256".equals(field.getKey())
                    && !"rsaKeyLayout".equals(field.getKey())) {
                throw new IllegalArgumentException(location + " contains unsupported field '"
                        + field.getKey() + "'");
            }
        }
        JsonElement pathElement = object.get("path");
        if (pathElement == null || !pathElement.isJsonPrimitive()
                || !pathElement.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(location + " field 'path' must be a string");
        }
        String path = requireText(pathElement.getAsString(), location + " field 'path'");
        String sha256 = null;
        if (object.has("sha256") && !object.get("sha256").isJsonNull()) {
            JsonElement hashElement = object.get("sha256");
            if (!hashElement.isJsonPrimitive() || !hashElement.getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException(location + " field 'sha256' must be a string");
            }
            sha256 = requireText(hashElement.getAsString(), location + " field 'sha256'")
                    .toLowerCase(Locale.ENGLISH);
            if (!sha256.matches(SHA_256_PATTERN)) {
                throw new IllegalArgumentException(location
                        + " field 'sha256' must contain 64 hexadecimal characters");
            }
        }
        RsaKeyLayout rsaKeyLayout = RsaKeyLayout.STANDARD;
        if (object.has("rsaKeyLayout") && !object.get("rsaKeyLayout").isJsonNull()) {
            JsonElement layoutElement = object.get("rsaKeyLayout");
            if (!layoutElement.isJsonPrimitive() || !layoutElement.getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException(location + " field 'rsaKeyLayout' must be a string");
            }
            rsaKeyLayout = RsaKeyLayout.parse(layoutElement.getAsString(), location + " field 'rsaKeyLayout'");
        }
        return new LibrarySpec(path, sha256, rsaKeyLayout);
    }

    private void validateConfiguredPathSyntax(String path, String location) {
        if (path.startsWith(CLASSPATH_PREFIX)) {
            normalizeClasspathResource(path.substring(CLASSPATH_PREFIX.length()), location);
            return;
        }
        if (!isPortableAbsolutePath(path)) {
            throw new IllegalArgumentException(location
                    + " must use an absolute filesystem path or classpath: resource: " + path);
        }
    }

    private String validateConfiguredLibraryFile(String vendorName, LibrarySpec spec) {
        final Path libraryPath;
        try {
            libraryPath = Paths.get(spec.path);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid SDF library path for vendor '" + vendorName
                    + "': " + spec.path, e);
        }
        if (!libraryPath.isAbsolute()) {
            throw new IllegalArgumentException("SDF library path for vendor '" + vendorName
                    + "' is not absolute on " + currentOs + ": " + spec.path);
        }
        String resolved = validateExistingFile("SDF library for vendor '" + vendorName + "'", libraryPath);
        if (spec.sha256 != null) {
            verifyFileSha256(Paths.get(resolved), spec.sha256,
                    "SDF library for vendor '" + vendorName + "'");
        }
        return resolved;
    }

    private String validateSystemPropertyFile(String propertyName, String description, String path) {
        final Path file;
        try {
            file = Paths.get(path);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("System property '" + propertyName
                    + "' is not a valid filesystem path: " + path, e);
        }
        if (!file.isAbsolute()) {
            throw new IllegalArgumentException("System property '" + propertyName
                    + "' must be an absolute filesystem path: " + path);
        }
        return validateExistingFile(description + " configured by '" + propertyName + "'", file);
    }

    private String validateExistingFile(String description, Path file) {
        Path normalized = file.normalize();
        if (!Files.exists(normalized)) {
            throw new IllegalArgumentException(description + " does not exist: " + normalized);
        }
        if (!Files.isRegularFile(normalized)) {
            throw new IllegalArgumentException(description + " is not a regular file: " + normalized);
        }
        try {
            normalized = normalized.toRealPath();
        } catch (IOException e) {
            throw new IllegalArgumentException(description + " cannot be resolved: " + normalized, e);
        }
        if (!Files.isReadable(normalized)) {
            throw new IllegalArgumentException(description + " is not readable: " + normalized);
        }
        return normalized.toString();
    }

    private String extractClasspathLibrary(LibrarySpec spec) {
        String resourcePath = normalizeClasspathResource(
                spec.path.substring(CLASSPATH_PREFIX.length()), "classpath SDF library");
        String cacheKey = resourcePath + "#" + (spec.sha256 == null ? "unverified" : spec.sha256);
        String cached = EXTRACTED_LIBRARIES.get(cacheKey);
        if (cached != null && Files.isRegularFile(Paths.get(cached))) {
            return cached;
        }

        synchronized (EXTRACTION_LOCK) {
            cached = EXTRACTED_LIBRARIES.get(cacheKey);
            if (cached != null && Files.isRegularFile(Paths.get(cached))) {
                return cached;
            }
            return extractAndCache(resourcePath, spec.sha256, cacheKey);
        }
    }

    private String extractAndCache(String resourcePath, String expectedSha256, String cacheKey) {
        try (InputStream raw = SDFConfig.class.getResourceAsStream(resourcePath)) {
            if (raw == null) {
                throw new IllegalStateException("Cannot find SDF native library resource: " + resourcePath);
            }
            Path extractionRoot = NativeExtractionRootHolder.ROOT;
            String fileName = Paths.get(resourcePath).getFileName().toString();
            Path temporaryFile = Files.createTempFile(extractionRoot, "extract-", ".tmp");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (DigestInputStream input = new DigestInputStream(raw, digest)) {
                Files.copy(input, temporaryFile, StandardCopyOption.REPLACE_EXISTING);
            }
            String actualSha256 = toHex(digest.digest());
            if (expectedSha256 != null && !expectedSha256.equals(actualSha256)) {
                Files.deleteIfExists(temporaryFile);
                throw new SecurityException("SHA-256 mismatch for SDF native library resource '" + resourcePath
                        + "': expected " + expectedSha256 + " but was " + actualSha256);
            }

            Path target = extractionRoot.resolve(actualSha256.substring(0, 16) + "-" + fileName);
            Files.move(temporaryFile, target, StandardCopyOption.REPLACE_EXISTING);
            restrictToOwner(target, "r-x------");
            target.toFile().deleteOnExit();
            String extracted = target.toAbsolutePath().normalize().toString();
            EXTRACTED_LIBRARIES.put(cacheKey, extracted);
            return extracted;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to extract SDF native library resource: " + resourcePath, e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private void verifyFileSha256(Path file, String expectedSha256, String description) {
        try (InputStream raw = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (DigestInputStream input = new DigestInputStream(raw, digest)) {
                byte[] buffer = new byte[8192];
                while (input.read(buffer) != -1) {
                    // DigestInputStream updates the digest while consuming the file.
                }
            }
            String actualSha256 = toHex(digest.digest());
            if (!expectedSha256.equals(actualSha256)) {
                throw new SecurityException("SHA-256 mismatch for " + description + ": expected "
                        + expectedSha256 + " but was " + actualSha256);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to calculate SHA-256 for " + description + ": " + file, e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static class NativeExtractionRootHolder {
        private static final Path ROOT = createExtractionRoot();
    }

    private static Path createExtractionRoot() {
        try {
            Path root = Files.createTempDirectory("liuzx-sdf-jce-native-");
            restrictToOwner(root, "rwx------");
            root.toFile().deleteOnExit();
            return root;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to create SDF native library extraction directory", e);
        }
    }

    private static void restrictToOwner(Path path, String permissions) {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions));
        } catch (UnsupportedOperationException ignored) {
            // Windows and other non-POSIX filesystems use their platform defaults.
        } catch (IOException e) {
            throw new IllegalStateException("Failed to secure extracted native library path: " + path, e);
        }
    }

    private String normalizeClasspathResource(String path, String location) {
        String normalized = path == null ? null : path.trim().replace('\\', '/');
        if (normalized == null || normalized.isEmpty()) {
            throw new IllegalArgumentException(location + " classpath resource must not be empty");
        }
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        String[] segments = normalized.split("/");
        for (String segment : segments) {
            if (".".equals(segment) || "..".equals(segment)) {
                throw new IllegalArgumentException(location
                        + " classpath resource must not contain '.' or '..': " + path);
            }
        }
        return normalized;
    }

    private boolean isPortableAbsolutePath(String path) {
        return path.startsWith("/")
                || path.startsWith("\\\\")
                || path.matches("^[A-Za-z]:[\\\\/].*");
    }

    private String requireText(String value, String description) {
        String result = trimToNull(value);
        if (result == null) {
            throw new IllegalArgumentException(description + " must not be blank");
        }
        return result;
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String detectOS() {
        String osName = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);
        if (osName.contains("mac") || osName.contains("darwin")) {
            return "macos";
        } else if (osName.contains("win")) {
            return "windows";
        } else if (osName.contains("nux")) {
            return "linux";
        }
        return "unknown";
    }

    private String detectArch() {
        String osArch = System.getProperty("os.arch", "generic").toLowerCase(Locale.ENGLISH);
        if (osArch.equals("amd64") || osArch.equals("x86_64") || osArch.equals("x86-64")) {
            return "x86_64";
        } else if (osArch.equals("aarch64") || osArch.equals("arm64")) {
            return "aarch64";
        }
        return "unknown";
    }

    private String toHex(byte[] value) {
        StringBuilder hex = new StringBuilder(value.length * 2);
        for (byte item : value) {
            hex.append(String.format(Locale.ENGLISH, "%02x", item & 0xff));
        }
        return hex.toString();
    }

    private static class LibrarySpec {
        private final String path;
        private final String sha256;
        private final RsaKeyLayout rsaKeyLayout;

        private LibrarySpec(String path, String sha256, RsaKeyLayout rsaKeyLayout) {
            this.path = path;
            this.sha256 = sha256;
            this.rsaKeyLayout = rsaKeyLayout;
        }
    }

    public enum RsaKeyLayout {
        STANDARD,
        PACKED;

        private static RsaKeyLayout parse(String value, String source) {
            String normalized = value == null ? "" : value.trim().toUpperCase(Locale.ENGLISH);
            try {
                return RsaKeyLayout.valueOf(normalized);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(source
                        + " must be 'standard' or 'packed', but was: " + value, e);
            }
        }
    }

    private static class ConfigData {
        @SerializedName("defaultVendor")
        String defaultVendor;
        @SerializedName("vendors")
        Map<String, VendorEntry> vendors;

        private static class VendorEntry {
            @SerializedName("platforms")
            Map<String, Map<String, JsonElement>> platforms;
        }
    }
}
