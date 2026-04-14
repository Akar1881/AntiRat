package com.akar1881.antirat.protection;

import com.akar1881.antirat.AntiRatMod;

import java.io.File;
import java.nio.file.*;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class FileSystemGuard {

    private static volatile boolean active = false;
    private static final Set<String> detectedFileAccess = ConcurrentHashMap.newKeySet();
    private static ScheduledExecutorService watcher;

    private static final String[] SENSITIVE_FILE_PATTERNS = {
        "launcher_profiles.json",
        "launcher_accounts.json",
        "launcher_accounts_microsoft_store.json",
        ".minecraft/launcher_profiles.json",
        "Microsoft/Edge/User Data",
        "Google/Chrome/User Data",
        "discord/Local Storage",
        "discordcanary/Local Storage",
        "discordptb/Local Storage",
        "Mozilla/Firefox/Profiles",
        "BraveSoftware/Brave-Browser",
        "Opera Software/Opera Stable",
        "Telegram Desktop/tdata",
        "Steam/config",
        "feather/accounts.json",
        "lunarclient/settings/game/accounts.json",
        "essentialgg",
        ".feather/accounts.json",
    };

    private static final String[] SENSITIVE_DIRECTORIES = {
        "AppData/Roaming/.minecraft",
        "AppData/Local/Packages/Microsoft.MinecraftUWP",
        "AppData/Roaming/discord",
        "AppData/Roaming/discordcanary",
        "AppData/Roaming/discordptb",
        "AppData/Local/Google/Chrome/User Data",
        "AppData/Local/Microsoft/Edge/User Data",
        "AppData/Roaming/Mozilla/Firefox",
        "AppData/Roaming/Opera Software",
        "AppData/Local/BraveSoftware",
        "AppData/Roaming/Telegram Desktop",
        "Library/Application Support/minecraft",
        "Library/Application Support/discord",
        ".steam",
    };

    private FileSystemGuard() {}

    public static void init() {
        if (active) return;
        active = true;

        watcher = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "AntiRat-FileGuard");
            t.setDaemon(true);
            return t;
        });
        watcher.scheduleAtFixedRate(FileSystemGuard::scanForSuspiciousFileAccess, 5, 15, TimeUnit.SECONDS);

        AntiRatMod.LOGGER.info("[AntiRat/FileSystem] File system guard active - monitoring {} sensitive patterns",
            SENSITIVE_FILE_PATTERNS.length + SENSITIVE_DIRECTORIES.length);
    }

    public static boolean isFileAccessAllowed(String filePath) {
        if (!active || filePath == null) return true;

        String normalizedPath = filePath.replace("\\", "/").toLowerCase();

        for (String pattern : SENSITIVE_FILE_PATTERNS) {
            if (normalizedPath.contains(pattern.toLowerCase())) {
                StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                if (!isLegitimateFileAccess(stack)) {
                    String detail = "Access to: " + filePath;
                    detectedFileAccess.add(detail);
                    AntiRatMod.LOGGER.error("[AntiRat/FileSystem] BLOCKED suspicious file access: {}", filePath);
                    logAccessStack(stack);
                    return false;
                }
            }
        }

        for (String dir : SENSITIVE_DIRECTORIES) {
            if (normalizedPath.contains(dir.toLowerCase())) {
                StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                if (!isLegitimateFileAccess(stack)) {
                    String detail = "Access to directory: " + filePath;
                    detectedFileAccess.add(detail);
                    AntiRatMod.LOGGER.error("[AntiRat/FileSystem] BLOCKED suspicious directory access: {}", filePath);
                    logAccessStack(stack);
                    return false;
                }
            }
        }

        return true;
    }

    private static boolean isLegitimateFileAccess(StackTraceElement[] stack) {
        for (StackTraceElement element : stack) {
            String className = element.getClassName();
            if (className.startsWith("net.minecraft.") ||
                className.startsWith("com.mojang.") ||
                className.startsWith("net.fabricmc.") ||
                className.startsWith("com.akar1881.antirat.") ||
                className.startsWith("java.util.logging.") ||
                className.startsWith("org.apache.logging.")) {
                return true;
            }
        }
        return false;
    }

    private static void logAccessStack(StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder("[AntiRat/FileSystem] Blocked access stack:\n");
        for (int i = 2; i < Math.min(stack.length, 15); i++) {
            sb.append("  at ").append(stack[i]).append("\n");
        }
        AntiRatMod.LOGGER.warn(sb.toString());
    }

    private static void scanForSuspiciousFileAccess() {
        if (!active) return;

        try {
            Thread[] threads = new Thread[Thread.activeCount() + 10];
            int count = Thread.enumerate(threads);

            for (int i = 0; i < count; i++) {
                Thread t = threads[i];
                if (t == null || !t.isAlive() || t == Thread.currentThread()) continue;

                StackTraceElement[] stack = t.getStackTrace();
                for (StackTraceElement element : stack) {
                    String className = element.getClassName();
                    String methodName = element.getMethodName().toLowerCase();

                    if ((className.startsWith("java.io.") || className.startsWith("java.nio.")) &&
                        (methodName.contains("read") || methodName.contains("open"))) {

                        boolean hasFileContext = false;
                        for (StackTraceElement other : stack) {
                            String otherMethod = other.getMethodName().toLowerCase();
                            String otherClass = other.getClassName().toLowerCase();
                            if (otherMethod.contains("token") || otherMethod.contains("steal") ||
                                otherMethod.contains("grab") || otherMethod.contains("browser") ||
                                otherMethod.contains("discord") || otherMethod.contains("cookie") ||
                                otherClass.contains("stealer") || otherClass.contains("grabber")) {
                                hasFileContext = true;
                                break;
                            }
                        }

                        if (hasFileContext) {
                            AntiRatMod.LOGGER.error(
                                "[AntiRat/FileSystem] KILLED thread '{}' - suspicious file I/O with stealer context",
                                t.getName());
                            t.interrupt();
                            break;
                        }
                    }
                }
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.debug("[AntiRat/FileSystem] Scan error: {}", e.getMessage());
        }
    }

    public static Set<String> getDetectedAccess() {
        return Set.copyOf(detectedFileAccess);
    }
}
