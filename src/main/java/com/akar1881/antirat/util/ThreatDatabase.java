package com.akar1881.antirat.util;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class ThreatDatabase {

    private static final Set<String> MALICIOUS_DOMAINS = ConcurrentHashMap.newKeySet();
    private static final Set<String> MALICIOUS_HASHES = ConcurrentHashMap.newKeySet();

    static {
        MALICIOUS_DOMAINS.add("raw.githubusercontent.com");
        MALICIOUS_DOMAINS.add("pastebin.com");
        MALICIOUS_DOMAINS.add("hastebin.com");
        MALICIOUS_DOMAINS.add("paste.ee");
        MALICIOUS_DOMAINS.add("ghostbin.com");
        MALICIOUS_DOMAINS.add("rentry.co");
        MALICIOUS_DOMAINS.add("anonfiles.com");
        MALICIOUS_DOMAINS.add("transfer.sh");
        MALICIOUS_DOMAINS.add("gofile.io");
        MALICIOUS_DOMAINS.add("file.io");
        MALICIOUS_DOMAINS.add("0x0.st");
        MALICIOUS_DOMAINS.add("catbox.moe");
        MALICIOUS_DOMAINS.add("litterbox.catbox.moe");
        MALICIOUS_DOMAINS.add("temp.sh");

        MALICIOUS_DOMAINS.add("canary.discord.com");
        MALICIOUS_DOMAINS.add("ptb.discord.com");

        MALICIOUS_DOMAINS.add("ipinfo.io");
        MALICIOUS_DOMAINS.add("ipapi.co");
        MALICIOUS_DOMAINS.add("ip-api.com");
        MALICIOUS_DOMAINS.add("ifconfig.me");
        MALICIOUS_DOMAINS.add("checkip.amazonaws.com");
        MALICIOUS_DOMAINS.add("whatismyip.com");
        MALICIOUS_DOMAINS.add("api.ipify.org");
        MALICIOUS_DOMAINS.add("ipwhois.app");
        MALICIOUS_DOMAINS.add("freegeoip.app");
        MALICIOUS_DOMAINS.add("extreme-ip-lookup.com");

        MALICIOUS_DOMAINS.add("ngrok.io");
        MALICIOUS_DOMAINS.add("ngrok-free.app");
        MALICIOUS_DOMAINS.add("serveo.net");
        MALICIOUS_DOMAINS.add("localhost.run");
        MALICIOUS_DOMAINS.add("loca.lt");
        MALICIOUS_DOMAINS.add("bore.digital");
    }

    private ThreatDatabase() {}

    public static boolean isKnownMaliciousDomain(String domain) {
        if (domain == null) return false;
        String lower = domain.toLowerCase();

        if (MALICIOUS_DOMAINS.contains(lower)) return true;

        for (String malicious : MALICIOUS_DOMAINS) {
            if (lower.endsWith("." + malicious)) return true;
        }

        if (lower.contains("discord") && lower.contains("webhook")) return true;
        if (lower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
            return !lower.startsWith("127.") && !lower.startsWith("192.168.") &&
                   !lower.startsWith("10.") && !lower.startsWith("172.");
        }

        return false;
    }

    public static boolean isKnownMaliciousHash(String hash) {
        if (hash == null || hash.isEmpty()) return false;
        return MALICIOUS_HASHES.contains(hash.toLowerCase());
    }

    public static void addMaliciousDomain(String domain) {
        MALICIOUS_DOMAINS.add(domain.toLowerCase());
    }

    public static void addMaliciousHash(String hash) {
        MALICIOUS_HASHES.add(hash.toLowerCase());
    }

    public static boolean isSuspiciousWebhookURL(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase();
        return lower.contains("discord.com/api/webhooks") ||
               lower.contains("discordapp.com/api/webhooks") ||
               lower.contains("api.telegram.org/bot") ||
               lower.contains("hooks.slack.com") ||
               lower.contains("/sendMessage?chat_id=");
    }
}
