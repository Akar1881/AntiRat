package com.akar1881.antirat;

import net.fabricmc.api.ClientModInitializer;

public class AntiRatClientMod implements ClientModInitializer {

    @Override
    public void onInitializeClient() {
        AntiRatMod.LOGGER.info("[AntiRat] Client-side protection layer initialized.");
    }
}
