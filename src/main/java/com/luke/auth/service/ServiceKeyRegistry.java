package com.luke.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Maps service-account API keys to engine userIds — the non-Clerk ingress for
 * robots / service accounts (mostly "Process Users").
 *
 * <p>Keys live in config (no DB; auth-engine stays stateless), as a comma-separated
 * list of {@code <secret>=<userId>[;exp=<epochSeconds>][;scope=<csv>]} entries.
 *
 * <p>Hardening (#39):
 * <ul>
 *   <li><b>Hashed at rest</b> — an entry whose left side is a 64-char hex string is
 *       treated as a SHA-256 hash of the real key, so config/secret-store leakage does
 *       not reveal usable keys. Plaintext entries still work (legacy) but log a
 *       deprecation warning. Generate a hash with {@code echo -n <key> | sha256sum}.</li>
 *   <li><b>Per-key expiry</b> — {@code ;exp=<epochSeconds>} makes a key stop working
 *       after that time with NO redeploy (issue short-lived keys; they self-revoke).</li>
 *   <li><b>Scope metadata</b> — {@code ;scope=<csv>} is carried for least-privilege +
 *       audit (recorded on issuance; downstream act-as scoping is a follow-up).</li>
 * </ul>
 * Comparison is constant-time per entry.
 */
@Component
public class ServiceKeyRegistry {

    private static final Logger log = LoggerFactory.getLogger(ServiceKeyRegistry.class);

    /** Result of a successful resolve: the identity plus non-secret metadata for audit. */
    public record Resolved(String userId, String keyId, String scope) {}

    private record Entry(boolean hashed, byte[] secretOrHash, String userId, long expiryEpochSec,
                         String scope, String keyId) {}

    private final List<Entry> entries = new ArrayList<>();

    public ServiceKeyRegistry(@Value("${luke.auth.service.keys:}") String raw) {
        if (raw != null && !raw.isBlank()) {
            for (String pair : raw.split(",")) {
                Entry e = parse(pair.trim());
                if (e != null) {
                    entries.add(e);
                }
            }
        }
        long expiring = entries.stream().filter(e -> e.expiryEpochSec() > 0).count();
        long plaintext = entries.stream().filter(e -> !e.hashed()).count();
        log.info("ServiceKeyRegistry: {} service key(s) configured ({} hashed, {} with expiry)",
                entries.size(), entries.size() - plaintext, expiring);
        if (plaintext > 0) {
            log.warn("ServiceKeyRegistry: {} service key(s) are PLAINTEXT in config (#39) — "
                    + "store SHA-256 hashes instead (echo -n <key> | sha256sum).", plaintext);
        }
    }

    private static Entry parse(String entry) {
        if (entry.isEmpty()) return null;
        int eq = entry.indexOf('=');
        if (eq <= 0) return null;
        String left = entry.substring(0, eq).trim();
        String[] meta = entry.substring(eq + 1).split(";");
        String userId = meta[0].trim();
        if (userId.isEmpty()) return null;
        long exp = 0L;
        String scope = null;
        for (int i = 1; i < meta.length; i++) {
            String m = meta[i].trim();
            if (m.startsWith("exp=")) {
                try {
                    exp = Long.parseLong(m.substring(4).trim());
                } catch (NumberFormatException ignored) {
                    log.warn("ServiceKeyRegistry: ignoring malformed exp in a key entry");
                }
            } else if (m.startsWith("scope=")) {
                scope = m.substring(6).trim();
            }
        }
        boolean hashed = left.length() == 64 && left.chars().allMatch(c ->
                (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'));
        // keyId is a NON-secret label for audit: for a hash, its first 8 chars; for
        // plaintext, a sha256 prefix of the secret (never the secret itself).
        String keyId = hashed ? left.substring(0, 8) : sha256Hex(left).substring(0, 8);
        return new Entry(hashed, left.toLowerCase().getBytes(StandardCharsets.UTF_8), userId, exp, scope, keyId);
    }

    public boolean isEnabled() {
        return !entries.isEmpty();
    }

    /**
     * Resolve a presented key to its identity + metadata, or {@code null} if no entry
     * matches or the matching entry has expired. Constant-time comparison per entry.
     */
    public Resolved resolve(String key) {
        if (key == null || key.isBlank()) return null;
        byte[] rawBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] hashBytes = sha256Hex(key).getBytes(StandardCharsets.UTF_8);
        long now = Instant.now().getEpochSecond();
        Entry match = null;
        for (Entry e : entries) {
            byte[] candidate = e.hashed() ? hashBytes : rawBytes;
            if (MessageDigest.isEqual(e.secretOrHash(), candidate)) {
                match = e;
            }
        }
        if (match == null) return null;
        if (match.expiryEpochSec() > 0 && now >= match.expiryEpochSec()) {
            log.warn("ServiceKeyRegistry: rejected EXPIRED service key (keyId={}, userId={})",
                    match.keyId(), match.userId());
            return null;
        }
        return new Resolved(match.userId(), match.keyId(), match.scope());
    }

    private static String sha256Hex(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(d); // lowercase hex
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e); // never on a standard JRE
        }
    }
}
