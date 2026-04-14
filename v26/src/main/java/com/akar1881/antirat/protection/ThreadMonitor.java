package com.akar1881.antirat.protection;

import com.akar1881.antirat.AntiRatMod;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class ThreadMonitor {

    private static volatile boolean active = false;
    private static final Set<String> killedThreads = ConcurrentHashMap.newKeySet();
    private static ScheduledExecutorService monitor;

    private static final String[] SUSPICIOUS_THREAD_NAMES = {
        "rat-", "stealer", "grabber", "exfil", "token-grab",
        "webhook-send", "c2-", "backdoor", "payload",
        "keylog", "clipboard-", "screen-grab",
        "browser-steal", "cookie-grab", "discord-token",
        "session-hijack", "remote-shell", "reverse-shell",
        "data-exfil", "credential", "password-dump",
    };

    private static final String[] SUSPICIOUS_THREAD_PATTERNS_IN_STACK = {
        "ProcessBuilder",
        "Runtime.exec",
        "Runtime.getRuntime",
    };

    private ThreadMonitor() {}

    public static void init() {
        if (active) return;
        active = true;

        monitor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "AntiRat-ThreadMonitor");
            t.setDaemon(true);
            return t;
        });
        monitor.scheduleAtFixedRate(ThreadMonitor::scan, 3, 5, TimeUnit.SECONDS);

        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            String name = t.getName().toLowerCase();
            for (String suspicious : SUSPICIOUS_THREAD_NAMES) {
                if (name.contains(suspicious)) {
                    AntiRatMod.LOGGER.error("[AntiRat/Thread] Suspicious thread '{}' crashed: {}",
                        t.getName(), e.getMessage());
                    return;
                }
            }
        });

        AntiRatMod.LOGGER.info("[AntiRat/Thread] Thread monitor active");
    }

    private static void scan() {
        if (!active) return;

        try {
            Thread[] threads = new Thread[Thread.activeCount() + 20];
            int count = Thread.enumerate(threads);

            for (int i = 0; i < count; i++) {
                Thread t = threads[i];
                if (t == null || !t.isAlive() || t == Thread.currentThread()) continue;

                String threadName = t.getName().toLowerCase();

                for (String suspicious : SUSPICIOUS_THREAD_NAMES) {
                    if (threadName.contains(suspicious)) {
                        killThread(t, "Suspicious thread name: " + t.getName());
                        break;
                    }
                }

                if (!t.isAlive()) continue;

                StackTraceElement[] stack = t.getStackTrace();
                if (stack.length == 0) continue;

                boolean hasProcessBuilder = false;
                boolean hasSuspiciousContext = false;

                for (StackTraceElement element : stack) {
                    String className = element.getClassName();
                    String methodName = element.getMethodName();

                    if (className.equals("java.lang.ProcessBuilder") && methodName.equals("start")) {
                        hasProcessBuilder = true;
                    }
                    if (className.equals("java.lang.Runtime") &&
                        (methodName.equals("exec") || methodName.equals("getRuntime"))) {
                        hasProcessBuilder = true;
                    }

                    String lowerClass = className.toLowerCase();
                    if (lowerClass.contains("stealer") || lowerClass.contains("rat") ||
                        lowerClass.contains("grabber") || lowerClass.contains("exfil") ||
                        lowerClass.contains("payload") || lowerClass.contains("backdoor")) {
                        hasSuspiciousContext = true;
                    }
                }

                if (hasProcessBuilder && hasSuspiciousContext) {
                    killThread(t, "Process execution from suspicious context");
                    logThreadStack(t.getName(), stack);
                }

                if (hasSuspiciousContext) {
                    boolean makingNetworkCall = false;
                    for (StackTraceElement element : stack) {
                        String className = element.getClassName();
                        if (className.startsWith("java.net.") || className.startsWith("sun.net.") ||
                            className.contains("HttpClient") || className.contains("URLConnection") ||
                            className.contains("Socket")) {
                            makingNetworkCall = true;
                            break;
                        }
                    }

                    if (makingNetworkCall) {
                        killThread(t, "Network call from suspicious context");
                        logThreadStack(t.getName(), stack);
                    }
                }
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.debug("[AntiRat/Thread] Scan error: {}", e.getMessage());
        }
    }

    private static void killThread(Thread t, String reason) {
        String key = t.getName() + " - " + reason;
        if (killedThreads.add(key)) {
            AntiRatMod.LOGGER.error("[AntiRat/Thread] KILLED thread '{}': {}", t.getName(), reason);
            t.interrupt();
        }
    }

    private static void logThreadStack(String threadName, StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder();
        sb.append("[AntiRat/Thread] Stack for killed thread '").append(threadName).append("':\n");
        for (int i = 0; i < Math.min(stack.length, 20); i++) {
            sb.append("  at ").append(stack[i]).append("\n");
        }
        AntiRatMod.LOGGER.warn(sb.toString());
    }

    public static Set<String> getKilledThreads() {
        return Set.copyOf(killedThreads);
    }
}
