package com.luke.auth.webhook;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Verifies the {@code WorkOS-Signature} on an inbound webhook (#38).
 *
 * <p>WorkOS signs each webhook with a header of the form {@code t=<unixSeconds>, v1=<hex>},
 * where the HMAC-SHA256 is computed over {@code "<t>.<rawBody>"} using the endpoint's signing
 * secret. This checks the MAC in constant time and rejects stale timestamps to blunt replay.
 *
 * <p><b>Default-lenient:</b> with no {@code WORKOS_WEBHOOK_SECRET} configured (dev/qa), the
 * verifier is {@linkplain #isEnabled() disabled} and the webhook endpoint returns 404 — the
 * app still boots and serves; it simply doesn't accept directory-sync events until configured.
 */
@Component
public class WorkosWebhookVerifier {

    /** Reject signatures whose timestamp is more than this far from now (replay window). */
    private static final long TOLERANCE_SECONDS = 300;

    private final byte[] secret;

    public WorkosWebhookVerifier(@Value("${luke.auth.workos.webhook-secret:}") String secret) {
        this.secret = StringUtils.hasText(secret) ? secret.getBytes(StandardCharsets.UTF_8) : null;
    }

    /** True only when a signing secret is configured; otherwise the endpoint stays disabled. */
    public boolean isEnabled() {
        return secret != null;
    }

    /**
     * @param signatureHeader the raw {@code WorkOS-Signature} header
     * @param rawBody         the exact request body bytes (verbatim — do not re-serialize)
     * @param nowEpochSeconds current time in unix seconds (injected for testability)
     * @return true iff the signature is present, fresh, and a valid HMAC of {@code "<t>.<body>"}
     */
    public boolean verify(String signatureHeader, byte[] rawBody, long nowEpochSeconds) {
        if (secret == null || signatureHeader == null || rawBody == null) {
            return false;
        }
        String timestamp = null;
        String provided = null;
        for (String part : signatureHeader.split(",")) {
            String p = part.trim();
            if (p.startsWith("t=")) {
                timestamp = p.substring(2).trim();
            } else if (p.startsWith("v1=")) {
                provided = p.substring(3).trim();
            }
        }
        if (timestamp == null || provided == null) {
            return false;
        }
        long ts;
        try {
            ts = Long.parseLong(timestamp);
        } catch (NumberFormatException e) {
            return false;
        }
        if (Math.abs(nowEpochSeconds - ts) > TOLERANCE_SECONDS) {
            return false; // stale or far-future — likely a replay
        }

        byte[] expected = hmacSha256(secret, (ts + ".").getBytes(StandardCharsets.UTF_8), rawBody);
        byte[] providedBytes = fromHex(provided);
        return providedBytes != null && MessageDigest.isEqual(expected, providedBytes);
    }

    private static byte[] hmacSha256(byte[] key, byte[] prefix, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(prefix);
            mac.update(body);
            return mac.doFinal();
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 unavailable", e);
        }
    }

    /** Parse lowercase/uppercase hex to bytes, or null if malformed. */
    private static byte[] fromHex(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            return null;
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                return null;
            }
            out[i / 2] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
