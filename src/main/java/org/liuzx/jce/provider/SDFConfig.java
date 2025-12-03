package org.liuzx.jce.provider;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;

public class SDFConfig {

    private static final String CONFIG_FILE = "/sdf-config.json";
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
        return path;
    }

    public String getDefaultLibraryPath() {
        return getLibraryPath(defaultVendor);
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
