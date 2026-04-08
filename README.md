# AntiRat

**A Fabric mod that protects your Minecraft account from token-stealing RAT mods.**

AntiRat runs silently in the background and defends your session token, account credentials, and personal data from malicious mods. If a RAT mod is installed alongside AntiRat, it will be detected, blocked, and reported — keeping your account safe.

---

## Summary

AntiRat is a client-side security mod for Minecraft (Fabric) that provides **6 layers of real-time protection** against malicious mods (commonly known as "RATs" or "token stealers"). It monitors network activity, guards your session token, scans loaded mods, watches file access, detects reflection abuse, and kills suspicious threads — all automatically with zero configuration needed.

---

## Features

### Network Guard
Intercepts all HTTP/HTTPS connections and enforces a domain whitelist. Blocks outbound connections to:
- Discord/Telegram webhooks (used to exfiltrate tokens)
- Paste sites (pastebin, hastebin, paste.ee, etc.)
- IP lookup services (ipinfo.io, ip-api.com, etc.)
- Tunneling services (ngrok, serveo, localhost.run, etc.)
- File upload services (anonfiles, transfer.sh, gofile, etc.)
- Raw IP address connections from untrusted code

Only official Mojang, Microsoft, Fabric, and community domains (Modrinth, CurseForge) are whitelisted by default. You can add your own trusted domains via the config file — see [Configuration](#configuration).

### Token Protector
Monitors all running threads for unauthorized access to your Minecraft session token. A watchdog thread scans every 5 seconds and interrupts any suspicious thread attempting to read token-related fields.

### Session Mixin (Direct Token Guard)
Hooks directly into `Session.getAccessToken()` using Mixin. Only trusted callers (Minecraft, Mojang, Fabric internals) can access the real token. Any untrusted mod that tries to read your access token gets a blocked response — the real token is never exposed.

### File System Guard
Monitors file I/O and blocks suspicious access to:
- Minecraft launcher profiles and account files
- Browser data (Chrome, Firefox, Edge, Brave, Opera)
- Discord, Discord Canary, and Discord PTB local storage
- Telegram Desktop session data
- Steam configuration files
- Feather, Lunar Client, and Essential account files

### Mod Scanner
Scans all loaded mods at startup and periodically checks the mods folder for:
- Suspicious class names (stealer, grabber, backdoor, keylogger, etc.)
- Known malicious bytecode strings (webhook URLs, exfiltration patterns)
- Known malicious JAR file hashes
- Discord/Telegram webhook URLs embedded in code

### Thread Monitor
Continuously monitors all running threads and kills any that:
- Have suspicious names (stealer, rat, backdoor, payload, etc.)
- Execute system commands (ProcessBuilder/Runtime.exec) from suspicious contexts
- Make network calls from code with stealer/grabber class patterns

### Reflection Guard
Detects and blocks unauthorized reflective access to sensitive Minecraft authentication classes:
- `Session` and its token fields
- `YggdrasilAuthenticationService`
- `MinecraftSessionService`
- `GameProfile`

---

## Installation

1. Install [Fabric Loader](https://fabricmc.net/use/installer/) (0.16.0+) for Minecraft 1.21.1
2. Download `anti-rat-1.0.0.jar` from the [Releases page](https://github.com/Akar1881/AntiRat/releases)
3. Place the JAR in your `.minecraft/mods/` folder
4. Launch Minecraft — AntiRat activates automatically

**Requirements:**
- Minecraft 1.21.1
- Fabric Loader 0.16.0+
- Java 21+

---

## Configuration

AntiRat creates a config file at `.minecraft/config/antirat_trusted_domains.json` on first launch.

### Adding Trusted Domains

If you use mods that need to connect to specific domains (like Skyblocker, custom APIs, etc.), add them to the config file:

```json
{
  "comment": "Add domains you trust here. These domains will be allowed through AntiRat's network guard. One domain per entry. Subdomains are automatically included (e.g. 'example.com' also allows 'api.example.com').",
  "trusted_domains": [
    "minecraft.net",
    "mojang.com",
    "fabricmc.net",
    "modrinth.com",
    "curseforge.com",
    "api.skyblocker.com",
    "hysky.de",
    "sky.coflnet.com"
  ]
}
```

**How it works:**
- Adding `example.com` automatically allows `api.example.com`, `cdn.example.com`, and all other subdomains
- Changes take effect on next game launch
- The default config includes Mojang, Fabric, Modrinth, and CurseForge domains

---

## How It Works

When Minecraft starts, AntiRat initializes all 6 protection systems before any other mod code can run. Here's what happens:

1. **Network Guard** installs a URL interceptor that checks every outbound HTTP/HTTPS connection against the whitelist and threat database
2. **Trusted Domain Config** loads your custom trusted domains from the config file
3. **Token Protector** starts a watchdog thread that scans all running threads every 5 seconds
4. **Reflection Guard** monitors for unauthorized reflective access to auth classes
5. **File System Guard** watches for suspicious file I/O targeting credential files
6. **Mod Scanner** scans all loaded mod JARs for malicious patterns and signatures
7. **Thread Monitor** continuously watches for and kills suspicious threads

If any malicious activity is detected, AntiRat will:
- **Block** the connection/access immediately
- **Log** full details including the offending mod and call stack
- **Kill** suspicious threads via interruption
- **Alert** with clear error messages in the game log

---

## Compatibility

AntiRat is designed to work alongside other Fabric mods without issues. It uses a trust-based approach:

- **Minecraft, Mojang, and Fabric** code is always trusted
- **Known mod platforms** (Modrinth, CurseForge) are whitelisted by default
- **Your custom domains** can be added via the config file
- **Suspicious behavior** is only flagged when code patterns match known RAT signatures

If a legitimate mod is being blocked, simply add its domain to `antirat_trusted_domains.json`.

---

## Building from Source

```bash
git clone https://github.com/Akar1881/AntiRat.git
cd AntiRat
./gradlew build
```

The output JAR will be in `build/libs/anti-rat-1.0.0.jar`.

---

## FAQ

**Q: Will this slow down my game?**
A: No. AntiRat uses lightweight daemon threads that run in the background with minimal CPU usage.

**Q: Can a RAT mod bypass AntiRat?**
A: AntiRat provides strong protection through multiple layers, but since all mods run in the same Java process, a highly sophisticated attacker could theoretically find ways around it. AntiRat makes this significantly harder and catches the vast majority of known RAT techniques. Always download mods from trusted sources as your first line of defense.

**Q: My other mod stopped working after installing AntiRat.**
A: That mod is likely trying to connect to a domain not on the whitelist. Add the domain to your `antirat_trusted_domains.json` config file. If the mod is accessing your session token or auth data, that is suspicious and AntiRat is correctly blocking it.

**Q: Does AntiRat send any data anywhere?**
A: No. AntiRat is completely offline and never sends any data. It only monitors and blocks outbound connections from other mods.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**Made by Akar1881**
