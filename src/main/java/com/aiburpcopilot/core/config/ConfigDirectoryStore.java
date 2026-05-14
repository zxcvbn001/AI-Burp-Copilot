package com.aiburpcopilot.core.config;

import java.util.prefs.Preferences;

public final class ConfigDirectoryStore {

    private static final String KEY_CONFIG_DIR = "configDir";
    private static final Preferences PREFS =
            Preferences.userNodeForPackage(ConfigDirectoryStore.class);

    private ConfigDirectoryStore() {}

    public static String load() {
        String value = PREFS.get(KEY_CONFIG_DIR, "");
        return value != null ? value.trim() : "";
    }

    public static void save(String directory) {
        if (directory == null || directory.isBlank()) {
            PREFS.remove(KEY_CONFIG_DIR);
            return;
        }
        PREFS.put(KEY_CONFIG_DIR, directory.trim());
    }
}
