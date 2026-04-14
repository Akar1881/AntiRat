package com.akar1881.antirat.protection;

import com.akar1881.antirat.AntiRatMod;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class ReflectionGuard {

    private static volatile boolean active = false;
    private static final Set<String> detectedReflectionAbuse = ConcurrentHashMap.newKeySet();
    private static ScheduledExecutorService scanner;

    private static final String[] PROTECTED_CLASSES = {
        "net.minecraft.client.session.Session",
        "net.minecraft.client.MinecraftClient",
        "com.mojang.authlib.yggdrasil.YggdrasilMinecraftSessionService",
        "com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService",
        "com.mojang.authlib.minecraft.MinecraftSessionService",
        "com.mojang.authlib.GameProfile",
    };

    private static final String[] PROTECTED_FIELDS = {
        "accessToken", "token", "session", "username",
        "uuid", "xuid", "clientToken", "selectedProfile",
    };

    private ReflectionGuard() {}

    public static void init() {
        if (active) return;
        active = true;

        scanner = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "AntiRat-ReflectionGuard");
            t.setDaemon(true);
            return t;
        });
        scanner.scheduleAtFixedRate(ReflectionGuard::scanForReflectionAbuse, 3, 8, TimeUnit.SECONDS);

        AntiRatMod.LOGGER.info("[AntiRat/Reflection] Reflection guard active - protecting {} classes",
            PROTECTED_CLASSES.length);
    }

    private static void scanForReflectionAbuse() {
        if (!active) return;

        try {
            Thread[] threads = new Thread[Thread.activeCount() + 10];
            int count = Thread.enumerate(threads);

            for (int i = 0; i < count; i++) {
                Thread t = threads[i];
                if (t == null || !t.isAlive() || t == Thread.currentThread()) continue;

                StackTraceElement[] stack = t.getStackTrace();
                boolean foundReflection = false;
                boolean foundSensitiveTarget = false;
                String sensitiveTarget = null;

                for (StackTraceElement element : stack) {
                    String className = element.getClassName();
                    String methodName = element.getMethodName();

                    if (className.equals("java.lang.reflect.Field") && methodName.equals("get")) {
                        foundReflection = true;
                    }
                    if (className.equals("java.lang.reflect.Field") && methodName.equals("setAccessible")) {
                        foundReflection = true;
                    }
                    if (className.equals("java.lang.reflect.Method") && methodName.equals("invoke")) {
                        foundReflection = true;
                    }
                    if (className.equals("java.lang.Class") && methodName.equals("getDeclaredField")) {
                        foundReflection = true;
                    }

                    for (String protectedClass : PROTECTED_CLASSES) {
                        if (className.equals(protectedClass) || className.startsWith(protectedClass)) {
                            foundSensitiveTarget = true;
                            sensitiveTarget = className;
                            break;
                        }
                    }
                }

                if (foundReflection && foundSensitiveTarget) {
                    boolean isLegitimate = isLegitimateReflection(stack);
                    if (!isLegitimate) {
                        String detail = "Thread '" + t.getName() + "' reflecting on " + sensitiveTarget;
                        detectedReflectionAbuse.add(detail);
                        AntiRatMod.LOGGER.error("[AntiRat/Reflection] DETECTED reflection abuse: {}", detail);
                        logFullStack(t.getName(), stack);
                        t.interrupt();
                    }
                }
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.debug("[AntiRat/Reflection] Scan error: {}", e.getMessage());
        }
    }

    private static boolean isLegitimateReflection(StackTraceElement[] stack) {
        for (StackTraceElement element : stack) {
            String className = element.getClassName();
            if (className.startsWith("net.minecraft.") ||
                className.startsWith("com.mojang.") ||
                className.startsWith("net.fabricmc.") ||
                className.startsWith("org.spongepowered.") ||
                className.startsWith("com.akar1881.antirat.")) {
                return true;
            }
        }
        return false;
    }

    private static void logFullStack(String threadName, StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder();
        sb.append("[AntiRat/Reflection] Stack trace for thread '").append(threadName).append("':\n");
        for (int i = 0; i < Math.min(stack.length, 25); i++) {
            sb.append("  at ").append(stack[i]).append("\n");
        }
        AntiRatMod.LOGGER.warn(sb.toString());
    }

    public static boolean checkReflectiveAccess(Class<?> targetClass, String fieldOrMethodName) {
        if (!active) return true;

        String targetClassName = targetClass.getName();
        for (String protectedClass : PROTECTED_CLASSES) {
            if (targetClassName.equals(protectedClass)) {
                if (fieldOrMethodName != null) {
                    String lower = fieldOrMethodName.toLowerCase();
                    for (String pf : PROTECTED_FIELDS) {
                        if (lower.contains(pf.toLowerCase())) {
                            StackTraceElement[] stack = Thread.currentThread().getStackTrace();
                            if (!isLegitimateReflection(stack)) {
                                AntiRatMod.LOGGER.error(
                                    "[AntiRat/Reflection] BLOCKED reflective access to {}.{}",
                                    targetClassName, fieldOrMethodName);
                                return false;
                            }
                        }
                    }
                }
                break;
            }
        }
        return true;
    }

    public static Set<String> getDetectedAbuse() {
        return Set.copyOf(detectedReflectionAbuse);
    }
}
