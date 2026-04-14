package com.akar1881.antirat.mixin;

import com.akar1881.antirat.AntiRatMod;
import net.minecraft.client.Minecraft;
import net.minecraft.client.User;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import java.util.Set;

@Mixin(Minecraft.class)
public class MinecraftClientMixin {

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

    @Inject(method = "getUser", at = @At("HEAD"))
    private void onGetUser(CallbackInfoReturnable<User> cir) {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();

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
                AntiRatMod.LOGGER.warn("[AntiRat/Mixin] Untrusted mod '{}' accessed Minecraft.getUser()",
                    className);
                logStack(stack);
                return;
            }
        }
    }

    private void logStack(StackTraceElement[] stack) {
        StringBuilder sb = new StringBuilder("[AntiRat/Mixin] Session access stack:\n");
        for (int i = 2; i < Math.min(stack.length, 15); i++) {
            sb.append("  at ").append(stack[i]).append("\n");
        }
        AntiRatMod.LOGGER.debug(sb.toString());
    }
}
