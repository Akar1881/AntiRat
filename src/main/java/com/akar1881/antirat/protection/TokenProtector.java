package com.akar1881.antirat.protection;

import com.akar1881.antirat.AntiRatMod;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class TokenProtector {

    private static volatile boolean active = false;
    private static final Set<String> blockedAccessAttempts = ConcurrentHashMap.newKeySet();
    private static ScheduledExecutorService watchdog;

    private static final String[] SENSITIVE_CLASS_PATTERNS = {
        "net.minecraft.client.MinecraftClient",
        "net.minecraft.client.session.Session",
        "com.mojang.authlib",
        "com.mojang.authlib.minecraft.MinecraftSessionService",
        "com.mojang.authlib.yggdrasil",
        "net.minecraft.client.util.Session",
    };

    private static final String[] SENSITIVE_FIELD_NAMES = {
        "accessToken",
        "token",
        "session",
        "sessionToken",
        "authToken",
        "refreshToken",
        "xuid",
        "clientId",
    };

    private TokenProtector() {}

    public static void init() {
        if (active) return;
        active = true;

        watchdog = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "AntiRat-TokenWatchdog");
            t.setDaemon(true);
            return t;
        });

        watchdog.scheduleAtFixedRate(TokenProtector::monitorTokenAccess, 2, 5, TimeUnit.SECONDS);

        AntiRatMod.LOGGER.info("[AntiRat/Token] Token protection active - monitoring {} sensitive patterns",
            SENSITIVE_CLASS_PATTERNS.length);
    }

    public static boolean isAccessAllowed(String className, String fieldName, StackTraceElement[] callerStack) {
        if (!active) return true;

        boolean isSensitiveClass = false;
        for (String pattern : SENSITIVE_CLASS_PATTERNS) {
            if (className.contains(pattern) || className.startsWith(pattern)) {
                isSensitiveClass = true;
                break;
            }
        }

        boolean isSensitiveField = false;
        if (fieldName != null) {
            String lowerField = fieldName.toLowerCase();
            for (String sensitiveField : SENSITIVE_FIELD_NAMES) {
                if (lowerField.contains(sensitiveField.toLowerCase())) {
                    isSensitiveField = true;
                    break;
                }
            }
        }

        if (!isSensitiveClass && !isSensitiveField) return true;

        for (StackTraceElement element : callerStack) {
            String callerClass = element.getClassName();

            if (callerClass.startsWith("net.minecraft.") ||
                callerClass.startsWith("com.mojang.") ||
                callerClass.startsWith("net.fabricmc.") ||
                callerClass.startsWith("com.akar1881.antirat.")) {
                continue;
            }

            if (callerClass.startsWith("java.") || callerClass.startsWith("sun.") ||
                callerClass.startsWith("jdk.")) {
                continue;
            }

            String lowerCaller = callerClass.toLowerCase();
            if (lowerCaller.contains("stealer") || lowerCaller.contains("token") ||
                lowerCaller.contains("grab") || lowerCaller.contains("exfil") ||
                lowerCaller.contains("webhook") || lowerCaller.contains("rat")) {

                String attempt = callerClass + " -> " + className + "." + fieldName;
                blockedAccessAttempts.add(attempt);
                AntiRatMod.LOGGER.error("[AntiRat/Token] BLOCKED token access attempt: {}", attempt);
                return false;
            }
        }

        return true;
    }

    private static void monitorTokenAccess() {
        if (!active) return;

        try {
            Thread[] threads = new Thread[Thread.activeCount() + 10];
            int count = Thread.enumerate(threads);

            for (int i = 0; i < count; i++) {
                Thread t = threads[i];
                if (t == null || !t.isAlive()) continue;
                if (t == Thread.currentThread()) continue;

                StackTraceElement[] stack = t.getStackTrace();
                for (StackTraceElement element : stack) {
                    String className = element.getClassName();
                    String methodName = element.getMethodName().toLowerCase();

                    boolean accessingSensitive = false;
                    for (String pattern : SENSITIVE_CLASS_PATTERNS) {
                        if (className.contains(pattern)) {
                            accessingSensitive = true;
                            break;
                        }
                    }

                    if (accessingSensitive) {
                        boolean isLegitimate = isLegitimateAccess(stack);
                        if (!isLegitimate) {
                            AntiRatMod.LOGGER.error(
                                "[AntiRat/Token] SUSPICIOUS thread '{}' accessing sensitive class: {}",
                                t.getName(), className);
                            logSuspiciousStack(t.getName(), stack);
                        }
                    }

                    if (methodName.contains("gettoken") || methodName.contains("stealtoken") ||
                        methodName.contains("grabsession") || methodName.contains("exfiltrate")) {
                        AntiRatMod.LOGGER.error(
                            "[AntiRat/Token] KILLED thread '{}' with suspicious method: {}.{}",
                            t.getName(), className, element.getMethodName());
                        t.interrupt();
                        break;
                    }
                }
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.debug("[AntiRat/Token] Watchdog scan error: {}", e.getMessage());
        }
    }

    private static boolean isLegitimateAccess(StackTraceElement[] stack) {
        for (StackTraceElement element : stack) {
            String className = element.getClassName();
            if (className.startsWith("net.minecraft.") || className.startsWith("com.mojang.") ||
                className.startsWith("net.fabricmc.")) {
                return true;
            }
        }
        return false;
    }

    private static void logSuspiciousStack(String threadName, StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder();
        sb.append("[AntiRat/Token] Suspicious stack trace for thread '").append(threadName).append("':\n");
        for (int i = 0; i < Math.min(stack.length, 20); i++) {
            sb.append("  at ").append(stack[i]).append("\n");
        }
        AntiRatMod.LOGGER.warn(sb.toString());
    }

    public static Set<String> getBlockedAttempts() {
        return Set.copyOf(blockedAccessAttempts);
    }
}
