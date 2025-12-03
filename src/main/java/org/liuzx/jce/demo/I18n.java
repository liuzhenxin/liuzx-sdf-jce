package org.liuzx.jce.demo;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Properties;

public class I18n {

    private static final Properties messages = new Properties();

    static {
        // Initialize with a default locale to avoid errors on startup
        setLocale(Locale.ENGLISH);
    }

    public static void setLocale(Locale locale) {
        // This is a more robust, manual way of loading properties files, bypassing ResourceBundle's complex logic.
        String lang = locale.getLanguage();
        String resourceName = "i18n/messages_" + lang + ".properties";
        
        InputStream is = I18n.class.getClassLoader().getResourceAsStream(resourceName);

        // If the specific language file is not found, fall back to English
        if (is == null) {
            System.err.println("Resource file not found for locale '" + lang + "', falling back to English.");
            resourceName = "i18n/messages_en.properties";
            is = I18n.class.getClassLoader().getResourceAsStream(resourceName);
        }

        if (is == null) {
            // If even English is not found, something is fundamentally wrong with the classpath.
            throw new RuntimeException("FATAL: Could not find any resource files (e.g., 'i18n/messages_en.properties') on the classpath.");
        }

        try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
            messages.clear(); // Clear old properties
            messages.load(reader);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load properties for locale: " + lang, e);
        }
    }

    public static String get(String key) {
        return messages.getProperty(key, "!" + key + "!");
    }
}
