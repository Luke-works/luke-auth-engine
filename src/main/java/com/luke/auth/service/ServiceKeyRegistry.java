package com.luke.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
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
 *   <li><b>Live revocation</b> — a keyId can be added to an in-memory revocation set at
 *       runtime ({@link #revoke}) and is rejected by {@link #resolve} immediately, with
 *       NO restart or redeploy. The set is exposed via an operator-only endpoint on
 *       {@code ServiceTokenController}. (Persist across restarts by re-issuing the env /
 *       secret with an {@code exp} in the past, or by re-driving the endpoint on boot.)</li>
 *   <li><b>Usage metering / audit</b> — each key tracks a last-used epoch-second timestamp
 *       and a monotonic issuance counter ({@link #Usage}), maintained thread-safe. The
 *       issuing controller records these into the audit trail on every successful mint.</li>
 * </ul>
 * Comparison is constant-time per entry.
 *
 * <h2>Pluggable secret source (#39: "sourced from a secret manager")</h2>
 * <p>Key material is read through a {@link SecretSource} rather than being hard-wired to
 * the {@code luke.auth.service.keys} env var. The default {@code SecretSource} is the
 * config string, but a deployment that wants keys from AWS Secrets Manager / Vault / GCP
 * Secret Manager can supply a bean of type {@link SecretSource} whose {@link SecretSource#raw()}
 * fetches the same {@code <secret>=<userId>;...} line from that store — no other code
 * changes. That is the only part of the "secret manager" AC that needs external infra;
 * the registry itself is decoupled from where the material lives.
 */
@Component
public class ServiceKeyRegistry {

    private static final Logger log = LoggerFactory.getLogger(ServiceKeyRegistry.class);

    /**
     * Where the raw {@code <secret>=<userId>;...} key material comes from. The default is
     * the {@code luke.auth.service.keys} config value; a secret-manager-backed bean can
     * replace it without touching the registry. Kept a functional interface so a lambda
     * (e.g. {@code () -> secretsManager.getSecretValue("luke/service-keys")}) suffices.
     */
    @FunctionalInterface
    public interface SecretSource extends Supplier<String> {
        /** The raw comma-separated key material, or blank/null if none configured. */
        String raw();

        @Override
        default String get() {
            return raw();
        }
    }

    /** Result of a successful resolve: the identity plus non-secret metadata for audit. */
    public record Resolved(String userId, String keyId, String scope) {}

    /** Per-key usage snapshot for metering/audit: last-used epoch second + issuance count. */
    public record Usage(long lastUsedEpochSec, long issuanceCount) {}

    private record Entry(boolean hashed, byte[] secretOrHash, String userId, long expiryEpochSec,
                         String scope, String keyId) {}

    private final List<Entry> entries = new ArrayList<>();

    /** Live revocation list — keyIds revoked at runtime take effect on the next resolve. */
    private final Set<String> revokedKeyIds = ConcurrentHashMap.newKeySet();

    /** Per-key last-used timestamp (epoch seconds), updated on each successful resolve. */
    private final ConcurrentHashMap<String, AtomicLong> lastUsed = new ConcurrentHashMap<>();

    /** Per-key monotonic issuance counter, incremented on each successful resolve. */
    private final ConcurrentHashMap<String, AtomicLong> issuanceCount = new ConcurrentHashMap<>();

    /** Spring-wired constructor: default {@link SecretSource} is the config value. */
    @Autowired
    public ServiceKeyRegistry(@Value("${luke.auth.service.keys:}") String raw) {
        this((SecretSource) () -> raw);
    }

    /**
     * Core constructor taking a pluggable {@link SecretSource} — used directly by tests and
     * by any secret-manager integration. The material is read ONCE at construction (like the
     * env today); live changes flow through {@link #revoke}, not re-reads of the source.
     */
    public ServiceKeyRegistry(SecretSource source) {
        String raw = source != null ? source.raw() : null;
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
     * matches, the matching entry has expired, or its keyId has been revoked live.
     * Constant-time comparison per entry. On success, updates last-used + issuance count.
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
        if (revokedKeyIds.contains(match.keyId())) {
            log.warn("ServiceKeyRegistry: rejected REVOKED service key (keyId={}, userId={})",
                    match.keyId(), match.userId());
            return null;
        }
        if (match.expiryEpochSec() > 0 && now >= match.expiryEpochSec()) {
            log.warn("ServiceKeyRegistry: rejected EXPIRED service key (keyId={}, userId={})",
                    match.keyId(), match.userId());
            return null;
        }
        // Success: meter it. Thread-safe; created lazily per keyId.
        lastUsed.computeIfAbsent(match.keyId(), k -> new AtomicLong()).set(now);
        issuanceCount.computeIfAbsent(match.keyId(), k -> new AtomicLong()).incrementAndGet();
        return new Resolved(match.userId(), match.keyId(), match.scope());
    }

    /**
     * Revoke a keyId at runtime — takes effect on the very next {@link #resolve} with no
     * restart. Idempotent. Returns {@code true} if the keyId is a known configured key (so
     * the operator gets feedback for a typo'd keyId), {@code false} otherwise; either way the
     * id is added to the revocation set (revoking an unknown id is harmless and future-proof
     * if keys are rotated in from a secret source).
     */
    public boolean revoke(String keyId) {
        if (keyId == null || keyId.isBlank()) return false;
        String id = keyId.trim();
        revokedKeyIds.add(id);
        boolean known = entries.stream().anyMatch(e -> e.keyId().equals(id));
        log.warn("ServiceKeyRegistry: keyId={} REVOKED live (known={})", id, known);
        return known;
    }

    /** Un-revoke a keyId (operator undo). Returns whether it was in the revocation set. */
    public boolean unrevoke(String keyId) {
        if (keyId == null || keyId.isBlank()) return false;
        boolean removed = revokedKeyIds.remove(keyId.trim());
        if (removed) {
            log.warn("ServiceKeyRegistry: keyId={} un-revoked", keyId.trim());
        }
        return removed;
    }

    /** Whether a keyId is currently revoked. */
    public boolean isRevoked(String keyId) {
        return keyId != null && revokedKeyIds.contains(keyId.trim());
    }

    /** Immutable snapshot of currently-revoked keyIds. */
    public Set<String> revokedKeyIds() {
        return Set.copyOf(revokedKeyIds);
    }

    /**
     * Usage snapshot for a keyId: last-used epoch second (0 if never used) and issuance
     * count (0 if never issued). Never {@code null}.
     */
    public Usage usage(String keyId) {
        AtomicLong lu = lastUsed.get(keyId);
        AtomicLong ic = issuanceCount.get(keyId);
        return new Usage(lu != null ? lu.get() : 0L, ic != null ? ic.get() : 0L);
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
