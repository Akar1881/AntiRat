package com.akar1881.antirat.protection;

import com.akar1881.antirat.AntiRatMod;
import com.akar1881.antirat.util.ThreatDatabase;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.*;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class NetworkGuard {

    private static final Set<String> blockedConnections = ConcurrentHashMap.newKeySet();
    private static final Set<String> allowedDomains = ConcurrentHashMap.newKeySet();
    private static volatile boolean active = false;
    private static ScheduledExecutorService monitor;

    static {
        allowedDomains.add("mojang.com");
        allowedDomains.add("minecraft.net");
        allowedDomains.add("microsoft.com");
        allowedDomains.add("live.com");
        allowedDomains.add("xboxlive.com");
        allowedDomains.add("minecraftservices.com");
        allowedDomains.add("minecraftforge.net");
        allowedDomains.add("fabricmc.net");
        allowedDomains.add("curseforge.com");
        allowedDomains.add("modrinth.com");
        allowedDomains.add("optifine.net");
        allowedDomains.add("authserver.mojang.com");
        allowedDomains.add("sessionserver.mojang.com");
        allowedDomains.add("api.mojang.com");
        allowedDomains.add("api.minecraftservices.com");
        allowedDomains.add("textures.minecraft.net");
        allowedDomains.add("resources.download.minecraft.net");
        allowedDomains.add("libraries.minecraft.net");
        allowedDomains.add("launchermeta.mojang.com");
        allowedDomains.add("piston-data.mojang.com");
        allowedDomains.add("piston-meta.mojang.com");
        allowedDomains.add("login.microsoftonline.com");
        allowedDomains.add("login.live.com");
        allowedDomains.add("user.auth.xboxlive.com");
        allowedDomains.add("xsts.auth.xboxlive.com");
    }

    private NetworkGuard() {}

    public static void init() {
        if (active) return;
        active = true;

        installURLStreamInterceptor();

        monitor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "AntiRat-NetworkMonitor");
            t.setDaemon(true);
            return t;
        });
        monitor.scheduleAtFixedRate(NetworkGuard::scanActiveConnections, 5, 10, TimeUnit.SECONDS);

        AntiRatMod.LOGGER.info("[AntiRat/Network] Network guard installed with {} whitelisted domains", allowedDomains.size());
    }

    private static void installURLStreamInterceptor() {
        try {
            URLStreamHandlerFactory existingFactory = getExistingFactory();

            URLStreamHandlerFactory guardFactory = protocol -> {
                if ("http".equals(protocol) || "https".equals(protocol)) {
                    return new GuardedStreamHandler(protocol);
                }
                if (existingFactory != null) {
                    return existingFactory.createURLStreamHandler(protocol);
                }
                return null;
            };

            resetURLStreamHandlerFactory();
            URL.setURLStreamHandlerFactory(guardFactory);
            AntiRatMod.LOGGER.info("[AntiRat/Network] URL stream interceptor installed successfully");
        } catch (Error e) {
            AntiRatMod.LOGGER.warn("[AntiRat/Network] Could not install URL interceptor (factory already set), using fallback monitoring");
        } catch (Exception e) {
            AntiRatMod.LOGGER.warn("[AntiRat/Network] URL interceptor install error: {}", e.getMessage());
        }
    }

    private static URLStreamHandlerFactory getExistingFactory() {
        try {
            Field factoryField = URL.class.getDeclaredField("factory");
            factoryField.setAccessible(true);
            return (URLStreamHandlerFactory) factoryField.get(null);
        } catch (Exception e) {
            return null;
        }
    }

    private static void resetURLStreamHandlerFactory() {
        try {
            Field factoryField = URL.class.getDeclaredField("factory");
            factoryField.setAccessible(true);
            factoryField.set(null, null);
        } catch (Exception e) {
            AntiRatMod.LOGGER.debug("[AntiRat/Network] Could not reset URL factory field");
        }
    }

    private static final Set<String> TRUSTED_PREFIXES = Set.of(
        "net.minecraft.", "com.mojang.", "net.fabricmc.",
        "com.akar1881.antirat.", "java.", "javax.", "sun.", "jdk.",
        "org.spongepowered.", "org.objectweb.asm.",
        "org.apache.", "org.slf4j.", "io.netty.", "com.google.",
        "it.unimi.dsi."
    );

    public static boolean isConnectionAllowed(String host) {
        if (host == null || host.isEmpty()) return true;

        String lowerHost = host.toLowerCase();

        if (lowerHost.equals("localhost") || lowerHost.equals("127.0.0.1") ||
            lowerHost.equals("0.0.0.0") || lowerHost.startsWith("192.168.") ||
            lowerHost.startsWith("10.") || lowerHost.equals("::1")) {
            return true;
        }

        for (String allowed : allowedDomains) {
            if (lowerHost.equals(allowed) || lowerHost.endsWith("." + allowed)) {
                return true;
            }
        }

        if (ThreatDatabase.isKnownMaliciousDomain(lowerHost)) {
            AntiRatMod.LOGGER.error("[AntiRat/Network] BLOCKED KNOWN MALICIOUS CONNECTION to: {}", host);
            blockedConnections.add(host);
            return false;
        }

        StackTraceElement[] stack = Thread.currentThread().getStackTrace();

        boolean hasUntrustedCaller = false;
        String untrustedClass = null;
        for (StackTraceElement element : stack) {
            String className = element.getClassName();
            boolean trusted = false;
            for (String prefix : TRUSTED_PREFIXES) {
                if (className.startsWith(prefix)) {
                    trusted = true;
                    break;
                }
            }
            if (!trusted) {
                hasUntrustedCaller = true;
                untrustedClass = className;
                break;
            }
        }

        if (hasUntrustedCaller) {
            AntiRatMod.LOGGER.warn("[AntiRat/Network] Non-whitelisted mod '{}' connecting to unknown host: {}", untrustedClass, host);

            boolean suspiciousOrigin = analyzeStackForSuspicion(stack);
            if (suspiciousOrigin) {
                AntiRatMod.LOGGER.error("[AntiRat/Network] BLOCKED suspicious connection to: {} from {}", host, untrustedClass);
                logStack(stack);
                blockedConnections.add(host);
                return false;
            }
        }

        return true;
    }

    private static boolean analyzeStackForSuspicion(StackTraceElement[] stack) {
        for (StackTraceElement element : stack) {
            String className = element.getClassName().toLowerCase();
            String methodName = element.getMethodName().toLowerCase();

            if (className.contains("token") && (className.contains("steal") || className.contains("grab") || className.contains("exfil"))) {
                return true;
            }
            if (methodName.contains("steal") || methodName.contains("exfiltrate") || methodName.contains("grabtoken")) {
                return true;
            }
            if (className.contains("webhook") && !className.contains("mojang") && !className.contains("minecraft")) {
                return true;
            }
            if (className.contains("discord") && className.contains("hook")) {
                return true;
            }
            if (className.contains("rat") && (className.contains("client") || className.contains("payload") || className.contains("stealer"))) {
                return true;
            }
        }
        return false;
    }

    private static void logStack(StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder("[AntiRat/Network] Blocked call stack:\n");
        for (int i = 2; i < Math.min(stack.length, 15); i++) {
            sb.append("  at ").append(stack[i]).append("\n");
        }
        AntiRatMod.LOGGER.warn(sb.toString());
    }

    private static void scanActiveConnections() {
        if (!active) return;
        try {
            Thread[] threads = new Thread[Thread.activeCount() + 10];
            int count = Thread.enumerate(threads);
            for (int i = 0; i < count; i++) {
                Thread t = threads[i];
                if (t != null && t.isAlive()) {
                    String name = t.getName().toLowerCase();
                    if (name.contains("exfil") || name.contains("rat-") ||
                        name.contains("stealer") || name.contains("token-grab") ||
                        name.contains("webhook-send")) {
                        AntiRatMod.LOGGER.error("[AntiRat/Network] KILLED suspicious thread: {}", t.getName());
                        t.interrupt();
                    }
                }
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.debug("[AntiRat/Network] Thread scan error: {}", e.getMessage());
        }
    }

    public static Set<String> getBlockedConnections() {
        return Collections.unmodifiableSet(blockedConnections);
    }

    public static void addAllowedDomain(String domain) {
        allowedDomains.add(domain.toLowerCase());
    }

    private static class GuardedStreamHandler extends URLStreamHandler {
        private final String protocol;

        GuardedStreamHandler(String protocol) {
            this.protocol = protocol;
        }

        @Override
        protected URLConnection openConnection(URL url) throws IOException {
            String host = url.getHost();
            if (!isConnectionAllowed(host)) {
                throw new IOException("[AntiRat] Connection BLOCKED to suspicious host: " + host);
            }

            try {
                String handlerClassName = "sun.net.www.protocol." + protocol + ".Handler";
                Class<?> handlerClass = Class.forName(handlerClassName);
                URLStreamHandler handler = (URLStreamHandler) handlerClass.getDeclaredConstructor().newInstance();
                var method = URLStreamHandler.class.getDeclaredMethod("openConnection", URL.class);
                method.setAccessible(true);
                return (URLConnection) method.invoke(handler, url);
            } catch (Exception e) {
                throw new IOException("Failed to open connection to: " + host, e);
            }
        }
    }
}
