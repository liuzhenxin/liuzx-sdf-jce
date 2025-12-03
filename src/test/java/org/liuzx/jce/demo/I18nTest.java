package org.liuzx.jce.demo;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class I18nTest {

    @Test
    @DisplayName("Test switching between English and Chinese locales")
    public void testLocaleSwitching() {
        // 1. Test English locale
        I18n.setLocale(Locale.ENGLISH);
        String englishTitle = I18n.get("app.title");
        assertEquals("JCE Provider Test Menu", englishTitle, "Should return the English title.");

        String englishPrompt = I18n.get("prompt.threads");
        assertEquals("Enter number of threads", englishPrompt, "Should return the English prompt.");

        // 2. Test Chinese locale
        I18n.setLocale(Locale.CHINESE);
        String chineseTitle = I18n.get("app.title");
        // We use Unicode escapes in the test to ensure the test source file is always ASCII-compatible
        assertEquals("JCE Provider \u6d4b\u8bd5\u83dc\u5355", chineseTitle, "Should return the Chinese title.");

        String chinesePrompt = I18n.get("prompt.threads");
        assertEquals("\u8bf7\u8f93\u5165\u7ebf\u7a0b\u6570", chinesePrompt, "Should return the Chinese prompt.");

        // 3. Test switching back to English
        I18n.setLocale(Locale.ENGLISH);
        String englishTitleAgain = I18n.get("app.title");
        assertEquals("JCE Provider Test Menu", englishTitleAgain, "Should return the English title again after switching back.");
    }

    @Test
    @DisplayName("Test handling of missing keys")
    public void testMissingKey() {
        // Set a known locale
        I18n.setLocale(Locale.ENGLISH);

        String nonExistentKey = "this.key.does.not.exist";
        String result = I18n.get(nonExistentKey);

        // The get() method should return the key surrounded by "!" if not found
        assertEquals("!" + nonExistentKey + "!", result, "Should return the key itself as a fallback.");
    }
}
