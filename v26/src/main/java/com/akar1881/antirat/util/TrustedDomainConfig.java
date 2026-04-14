package com.akar1881.antirat.util;

import com.akar1881.antirat.AntiRatMod;
import com.akar1881.antirat.protection.NetworkGuard;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import net.fabricmc.loader.api.FabricLoader;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.file.*;
import java.util.*;

public final class TrustedDomainConfig {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static Path configFile;

    private TrustedDomainConfig() {}

    public static void load() {
        configFile = FabricLoader.getInstance().getConfigDir().resolve("antirat_trusted_domains.json");

        if (!Files.exists(configFile)) {
            createDefaultConfig();
        }

        try {
            String json = Files.readString(configFile);
            Type listType = new TypeToken<TrustedDomainsFile>() {}.getType();
            TrustedDomainsFile config = GSON.fromJson(json, TrustedDomainsFile.class);

            if (config != null && config.trusted_domains != null) {
                int count = 0;
                for (String domain : config.trusted_domains) {
                    String trimmed = domain.trim().toLowerCase();
                    if (!trimmed.isEmpty()) {
                        NetworkGuard.addAllowedDomain(trimmed);
                        count++;
                    }
                }
                AntiRatMod.LOGGER.info("[AntiRat/Config] Loaded {} trusted domains from config", count);
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.error("[AntiRat/Config] Failed to load trusted domains config: {}", e.getMessage());
            AntiRatMod.LOGGER.info("[AntiRat/Config] Recreating default config...");
            createDefaultConfig();
        }
    }

    private static void createDefaultConfig() {
        TrustedDomainsFile defaultConfig = new TrustedDomainsFile();
        defaultConfig.comment = "Add domains you trust here. These domains will be allowed through AntiRat's network guard. One domain per entry. Subdomains are automatically included (e.g. 'example.com' also allows 'api.example.com').";
        defaultConfig.trusted_domains = List.of(
            "minecraft.net",
            "mojang.com",
            "fabricmc.net",
            "modrinth.com",
            "curseforge.com"
        );

        try {
            Files.createDirectories(configFile.getParent());
            String json = GSON.toJson(defaultConfig);
            Files.writeString(configFile, json);
            AntiRatMod.LOGGER.info("[AntiRat/Config] Created default trusted domains config at: {}", configFile);
        } catch (IOException e) {
            AntiRatMod.LOGGER.error("[AntiRat/Config] Failed to create default config: {}", e.getMessage());
        }
    }

    public static void addDomain(String domain) {
        try {
            String json = Files.readString(configFile);
            TrustedDomainsFile config = GSON.fromJson(json, TrustedDomainsFile.class);

            if (config == null) {
                config = new TrustedDomainsFile();
                config.comment = "Add domains you trust here.";
                config.trusted_domains = new ArrayList<>();
            }

            List<String> domains = new ArrayList<>(config.trusted_domains);
            String trimmed = domain.trim().toLowerCase();
            if (!domains.contains(trimmed)) {
                domains.add(trimmed);
                config.trusted_domains = domains;
                Files.writeString(configFile, GSON.toJson(config));
                NetworkGuard.addAllowedDomain(trimmed);
                AntiRatMod.LOGGER.info("[AntiRat/Config] Added trusted domain: {}", trimmed);
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.error("[AntiRat/Config] Failed to add domain: {}", e.getMessage());
        }
    }

    private static class TrustedDomainsFile {
        String comment;
        List<String> trusted_domains;
    }
}
