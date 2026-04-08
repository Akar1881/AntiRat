package com.akar1881.antirat.mixin;

import com.akar1881.antirat.AntiRatMod;
import com.akar1881.antirat.protection.NetworkGuard;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import java.net.HttpURLConnection;
import java.net.URL;

@Mixin(HttpURLConnection.class)
public class HttpURLConnectionMixin {

    @Inject(method = "connect", at = @At("HEAD"), cancellable = true, remap = false)
    private void onConnect(CallbackInfo ci) {
        try {
            HttpURLConnection conn = (HttpURLConnection) (Object) this;
            URL url = conn.getURL();
            if (url != null) {
                String host = url.getHost();
                if (!NetworkGuard.isConnectionAllowed(host)) {
                    AntiRatMod.LOGGER.error("[AntiRat/Mixin] BLOCKED HTTP connection to: {}", url);
                    ci.cancel();
                }
            }
        } catch (Exception e) {
            AntiRatMod.LOGGER.debug("[AntiRat/Mixin] HTTP intercept error: {}", e.getMessage());
        }
    }
}
