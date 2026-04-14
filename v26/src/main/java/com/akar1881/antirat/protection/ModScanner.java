package com.akar1881.antirat.protection;

import com.akar1881.antirat.AntiRatMod;
import com.akar1881.antirat.util.ThreatDatabase;

import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public final class ModScanner {

    private static volatile boolean active = false;
    private static final Set<String> flaggedMods = ConcurrentHashMap.newKeySet();
    private static final Set<String> scannedJars = ConcurrentHashMap.newKeySet();
    private static ScheduledExecutorService scanner;

    private static final String[] SUSPICIOUS_CLASS_NAMES = {
        "stealer", "grabber", "exfiltrate", "ratclient",
        "tokenstealer", "tokengrabber", "discordgrab",
        "webhooksend", "webhookexfil", "browserstealer",
        "cookiesteal", "passwordgrab", "sessionhijack",
        "keylogger", "clipboardhijack", "screengrab",
        "remoteaccess", "backdoor", "payload", "c2client",
        "commandcontrol", "reverseshell",
    };

    private static final String[] SUSPICIOUS_STRINGS_IN_BYTECODE = {
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "api.telegram.org/bot",
        "/sendMessage?chat_id=",
        "token_steal",
        "grabToken",
        "stealToken",
        "getAccessToken",
        "exfilData",
        "webhook_url",
        "DISCORD_WEBHOOK",
        "pastebin.com/raw",
        "hastebin.com",
        "anonfiles.com",
        "transfer.sh",
        "gofile.io",
        "file.io",
    };

    private ModScanner() {}

    public static void init() {
        if (active) return;
        active = true;

        scanLoadedMods();

        scanner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "AntiRat-ModScanner");
            t.setDaemon(true);
            return t;
        });
        scanner.scheduleAtFixedRate(ModScanner::scanModsFolder, 30, 120, TimeUnit.SECONDS);

        AntiRatMod.LOGGER.info("[AntiRat/ModScanner] Initial scan complete. {} mods flagged.", flaggedMods.size());
    }

    private static void scanLoadedMods() {
        try {
            Collection<ModContainer> mods = FabricLoader.getInstance().getAllMods();
            AntiRatMod.LOGGER.info("[AntiRat/ModScanner] Scanning {} loaded mods...", mods.size());

            for (ModContainer mod : mods) {
                String modId = mod.getMetadata().getId();
                String modName = mod.getMetadata().getName();

                if (modId.equals(AntiRatMod.MOD_ID) || modId.equals("fabricloader") ||
                    modId.equals("fabric-api") || modId.equals("minecraft") ||
                    modId.equals("java") || modId.startsWith("fabric-")) {
                    continue;
                }

                String lowerName = modName.toLowerCase();
                String lowerId = modId.toLowerCase();

                for (String suspicious : SUSPICIOUS_CLASS_NAMES) {
                    if (lowerName.contains(suspicious) || lowerId.contains(suspicious)) {
                        flagMod(modId, modName, "Suspicious mod name/id contains: " + suspicious);
                        break;
                    }
                }

                mod.getRootPaths().forEach(rootPath -> {
                    try {
                        if (rootPath.toString().endsWith(".jar") || rootPath.getFileSystem().provider().getScheme().equals("jar")) {
                            scanJarContent(rootPath, modId, modName);
                        }
                    } catch (Exception e) {
                        AntiRatMod.LOGGER.debug("[AntiRat/ModScanner] Could not scan mod {}: {}", modId, e.getMessage());
                    }
                });
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.error("[AntiRat/ModScanner] Error scanning loaded mods", e);
        }
    }

    private static void scanJarContent(Path rootPath, String modId, String modName) {
        try {
            Files.walk(rootPath)
                .filter(p -> p.toString().endsWith(".class"))
                .forEach(classPath -> {
                    String className = classPath.toString()
                        .replace("/", ".")
                        .replace("\\", ".")
                        .replaceFirst("^\\.", "");

                    if (className.endsWith(".class")) {
                        className = className.substring(0, className.length() - 6);
                    }

                    String lowerClassName = className.toLowerCase();
                    for (String suspicious : SUSPICIOUS_CLASS_NAMES) {
                        if (lowerClassName.contains(suspicious)) {
                            flagMod(modId, modName, "Contains suspicious class: " + className);
                            return;
                        }
                    }

                    try {
                        byte[] bytes = Files.readAllBytes(classPath);
                        String content = new String(bytes);
                        for (String suspiciousString : SUSPICIOUS_STRINGS_IN_BYTECODE) {
                            if (content.contains(suspiciousString)) {
                                flagMod(modId, modName,
                                    "Class " + className + " contains suspicious string: " + suspiciousString);
                                return;
                            }
                        }
                    } catch (IOException ignored) {}
                });
        } catch (IOException e) {
            AntiRatMod.LOGGER.debug("[AntiRat/ModScanner] Error walking mod path: {}", e.getMessage());
        }
    }

    private static void scanModsFolder() {
        if (!active) return;

        try {
            Path modsDir = FabricLoader.getInstance().getGameDir().resolve("mods");
            if (!Files.exists(modsDir)) return;

            Files.list(modsDir)
                .filter(p -> p.toString().endsWith(".jar"))
                .forEach(jarPath -> {
                    String jarName = jarPath.getFileName().toString();
                    if (scannedJars.contains(jarName)) return;
                    scannedJars.add(jarName);

                    try {
                        String hash = computeHash(jarPath);
                        if (ThreatDatabase.isKnownMaliciousHash(hash)) {
                            flagMod(jarName, jarName, "KNOWN MALICIOUS JAR - Hash: " + hash);
                            return;
                        }

                        try (JarFile jar = new JarFile(jarPath.toFile())) {
                            Enumeration<JarEntry> entries = jar.entries();
                            while (entries.hasMoreElements()) {
                                JarEntry entry = entries.nextElement();
                                if (!entry.getName().endsWith(".class")) continue;

                                String className = entry.getName()
                                    .replace("/", ".").replace(".class", "");

                                String lowerClassName = className.toLowerCase();
                                for (String suspicious : SUSPICIOUS_CLASS_NAMES) {
                                    if (lowerClassName.contains(suspicious)) {
                                        flagMod(jarName, jarName,
                                            "Contains suspicious class: " + className);
                                        break;
                                    }
                                }

                                try (InputStream is = jar.getInputStream(entry)) {
                                    byte[] bytes = is.readAllBytes();
                                    String content = new String(bytes);
                                    for (String suspiciousString : SUSPICIOUS_STRINGS_IN_BYTECODE) {
                                        if (content.contains(suspiciousString)) {
                                            flagMod(jarName, jarName,
                                                "Contains suspicious string in " + className + ": " + suspiciousString);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    } catch (Exception e) {
                        AntiRatMod.LOGGER.debug("[AntiRat/ModScanner] Error scanning jar {}: {}",
                            jarName, e.getMessage());
                    }
                });
        } catch (Exception e) {
            AntiRatMod.LOGGER.debug("[AntiRat/ModScanner] Mods folder scan error: {}", e.getMessage());
        }
    }

    private static String computeHash(Path filePath) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = Files.readAllBytes(filePath);
            byte[] hash = digest.digest(bytes);
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static void flagMod(String modId, String modName, String reason) {
        String entry = modId + " (" + modName + "): " + reason;
        if (flaggedMods.add(entry)) {
            AntiRatMod.LOGGER.error("============================================");
            AntiRatMod.LOGGER.error("[AntiRat/ModScanner] FLAGGED SUSPICIOUS MOD!");
            AntiRatMod.LOGGER.error("  Mod: {} ({})", modName, modId);
            AntiRatMod.LOGGER.error("  Reason: {}", reason);
            AntiRatMod.LOGGER.error("  ACTION: Remove this mod immediately!");
            AntiRatMod.LOGGER.error("============================================");
        }
    }

    public static Set<String> getFlaggedMods() {
        return Set.copyOf(flaggedMods);
    }
}
