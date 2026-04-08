package com.akar1881.antirat;

import net.fabricmc.api.ModInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.akar1881.antirat.protection.NetworkGuard;
import com.akar1881.antirat.protection.TokenProtector;
import com.akar1881.antirat.protection.ReflectionGuard;
import com.akar1881.antirat.protection.FileSystemGuard;
import com.akar1881.antirat.protection.ModScanner;
import com.akar1881.antirat.protection.ThreadMonitor;
import com.akar1881.antirat.util.TrustedDomainConfig;

public class AntiRatMod implements ModInitializer {

    public static final String MOD_ID = "antirat";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    private static boolean initialized = false;

    @Override
    public void onInitialize() {
        if (initialized) {
            return;
        }
        initialized = true;

        LOGGER.info("==============================================");
        LOGGER.info("  AntiRat Mod v1.0.0 by Akar1881");
        LOGGER.info("  Initializing protection systems...");
        LOGGER.info("==============================================");

        try {
            NetworkGuard.init();
            LOGGER.info("[AntiRat] Network Guard: ACTIVE");
        } catch (Exception e) {
            LOGGER.error("[AntiRat] Failed to initialize Network Guard", e);
        }

        try {
            TrustedDomainConfig.load();
            LOGGER.info("[AntiRat] Trusted Domain Config: LOADED");
        } catch (Exception e) {
            LOGGER.error("[AntiRat] Failed to load trusted domain config", e);
        }

        try {
            TokenProtector.init();
            LOGGER.info("[AntiRat] Token Protector: ACTIVE");
        } catch (Exception e) {
            LOGGER.error("[AntiRat] Failed to initialize Token Protector", e);
        }

        try {
            ReflectionGuard.init();
            LOGGER.info("[AntiRat] Reflection Guard: ACTIVE");
        } catch (Exception e) {
            LOGGER.error("[AntiRat] Failed to initialize Reflection Guard", e);
        }

        try {
            FileSystemGuard.init();
            LOGGER.info("[AntiRat] File System Guard: ACTIVE");
        } catch (Exception e) {
            LOGGER.error("[AntiRat] Failed to initialize File System Guard", e);
        }

        try {
            ModScanner.init();
            LOGGER.info("[AntiRat] Mod Scanner: ACTIVE");
        } catch (Exception e) {
            LOGGER.error("[AntiRat] Failed to initialize Mod Scanner", e);
        }

        try {
            ThreadMonitor.init();
            LOGGER.info("[AntiRat] Thread Monitor: ACTIVE");
        } catch (Exception e) {
            LOGGER.error("[AntiRat] Failed to initialize Thread Monitor", e);
        }

        LOGGER.info("==============================================");
        LOGGER.info("  AntiRat Mod: ALL SYSTEMS ACTIVE");
        LOGGER.info("  Your account is protected!");
        LOGGER.info("==============================================");
    }
}
