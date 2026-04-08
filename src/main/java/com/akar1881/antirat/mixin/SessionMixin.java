package com.akar1881.antirat.mixin;

import com.akar1881.antirat.AntiRatMod;
import net.minecraft.client.session.Session;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import java.util.Set;

@Mixin(Session.class)
public class SessionMixin {

    private static final Set<String> TRUSTED_PREFIXES = Set.of(
        "net.minecraft.",
        "com.mojang.",
        "net.fabricmc.",
        "com.akar1881.antirat.",
        "java.",
        "javax.",
        "sun.",
        "jdk.",
        "org.spongepowered.",
        "org.objectweb.asm.",
        "org.apache.logging.",
        "org.slf4j."
    );

    @Inject(method = "getAccessToken", at = @At("HEAD"), cancellable = true)
    private void onGetAccessToken(CallbackInfoReturnable<String> cir) {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();

        boolean hasUntrustedCaller = false;
        String untrustedCallerClass = null;

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
                untrustedCallerClass = className;
                break;
            }
        }

        if (hasUntrustedCaller) {
            AntiRatMod.LOGGER.error("[AntiRat/Mixin] BLOCKED access token request from untrusted caller: {}",
                untrustedCallerClass);
            logCallerStack(stack);
            cir.setReturnValue("0");
            return;
        }
    }

    private void logCallerStack(StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder("[AntiRat/Mixin] Token access blocked - caller stack:\n");
        for (int i = 2; i < Math.min(stack.length, 15); i++) {
            sb.append("  at ").append(stack[i]).append("\n");
        }
        AntiRatMod.LOGGER.warn(sb.toString());
    }
}
