package org.liuzx.jce.provider;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;

public class SDFConfig {

    private static final String CONFIG_FILE = "/sdf-config.json";
    private static final String CLASSPATH_PREFIX = "classpath:";
    private static final String VENDOR_PROPERTY = "liuzx.sdf.vendor";
    private static final String LIBRARY_PATH_PROPERTY = "liuzx.sdf.library.path";
    private static final SDFConfig INSTANCE = new SDFConfig(); // Singleton instance

    private String defaultVendor;
    private Map<String, ConfigData.VendorEntry> vendors; // Now uses the dedicated data class

    private final String currentOs;
    private final String currentArch;

    private SDFConfig() {
        this.currentOs = detectOS();
        this.currentArch = detectArch();
        loadConfig();
    }

    public static SDFConfig getInstance() {
        return INSTANCE;
    }

    private void loadConfig() {
        try (InputStream is = SDFConfig.class.getResourceAsStream(CONFIG_FILE)) {
            if (is == null) {
                throw new RuntimeException("Cannot find resource file: " + CONFIG_FILE);
            }
            Gson gson = new Gson();
            // Deserialize directly into our dedicated ConfigData class
            ConfigData loadedConfigData = gson.fromJson(new InputStreamReader(is), ConfigData.class);

            // Copy data from the loaded POJO to the SDFConfig's fields
            this.defaultVendor = loadedConfigData.defaultVendor;
            this.vendors = Collections.unmodifiableMap(loadedConfigData.vendors); // Make it unmodifiable for safety

        } catch (Exception e) {
            throw new RuntimeException("Failed to load or parse SDF config: " + e.getMessage(), e);
        }
    }

    public String getLibraryPath(String vendorName) {
        String overridePath = trimToNull(System.getProperty(LIBRARY_PATH_PROPERTY));
        if (overridePath != null) {
            return normalizeLibraryPath(overridePath);
        }

        ConfigData.VendorEntry vendorEntry = vendors.get(vendorName);
        if (vendorEntry == null) {
            throw new IllegalStateException("No configuration found for vendor: " + vendorName);
        }
        if (vendorEntry.platforms == null) {
            throw new IllegalStateException("No 'platforms' section found for vendor: " + vendorName);
        }

        Map<String, String> archMap = vendorEntry.platforms.get(currentOs);
        if (archMap == null) {
            throw new IllegalStateException("Unsupported OS '" + currentOs + "' for vendor: " + vendorName);
        }

        String path = archMap.get(currentArch);
        if (path == null) {
            throw new IllegalStateException("Unsupported architecture '" + currentArch + "' for OS '" + currentOs + "' and vendor '" + vendorName + "'");
        }
        return normalizeLibraryPath(path);
    }

    public String getDefaultLibraryPath() {
        return getLibraryPath(getDefaultVendor());
    }

    public String getDefaultVendor() {
        String vendorOverride = trimToNull(System.getProperty(VENDOR_PROPERTY));
        return vendorOverride == null ? defaultVendor : vendorOverride;
    }

    public String getCurrentOs() {
        return currentOs;
    }

    public String getCurrentArch() {
        return currentArch;
    }

    private String normalizeLibraryPath(String path) {
        if (path.startsWith(CLASSPATH_PREFIX)) {
            return extractClasspathLibrary(path.substring(CLASSPATH_PREFIX.length()));
        }

        Path libraryPath = Paths.get(path);
        if (libraryPath.isAbsolute()) {
            return libraryPath.normalize().toString();
        }
        return Paths.get(System.getProperty("user.dir"), path).normalize().toString();
    }

    private String extractClasspathLibrary(String resourcePath) {
        String normalizedResourcePath = resourcePath.startsWith("/") ? resourcePath : "/" + resourcePath;
        try (InputStream is = SDFConfig.class.getResourceAsStream(normalizedResourcePath)) {
            if (is == null) {
                throw new IllegalStateException("Cannot find SDF native library resource: " + normalizedResourcePath);
            }

            String fileName = Paths.get(resourcePath).getFileName().toString();
            Path targetDir = Files.createTempDirectory("liuzx-sdf-jce-");
            Path targetFile = targetDir.resolve(fileName);
            Files.copy(is, targetFile, StandardCopyOption.REPLACE_EXISTING);
            targetFile.toFile().deleteOnExit();
            targetDir.toFile().deleteOnExit();
            return targetFile.toAbsolutePath().normalize().toString();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to extract SDF native library resource: " + normalizedResourcePath, e);
        }
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
        } else {
            return "unknown";
        }
    }

    private String detectArch() {
        String osArch = System.getProperty("os.arch", "generic").toLowerCase(Locale.ENGLISH);
        if (osArch.equals("amd64") || osArch.equals("x86_64")) {
            return "x86_64";
        } else if (osArch.equals("aarch64")) {
            return "aarch64";
        } else {
            return "unknown";
        }
    }

    /**
     * Dedicated POJO to map the structure of sdf-config.json
     */
    private static class ConfigData {
        @SerializedName("defaultVendor")
        String defaultVendor;
        @SerializedName("vendors")
        Map<String, VendorEntry> vendors;

        private static class VendorEntry {
            @SerializedName("platforms")
            Map<String, Map<String, String>> platforms;
        }
    }
}
