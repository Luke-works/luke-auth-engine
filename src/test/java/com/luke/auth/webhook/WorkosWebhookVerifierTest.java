package com.luke.auth.webhook;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

/**
 * #38 — the webhook signature check must accept a correctly-signed, fresh event and reject
 * everything else (tampered body, wrong secret, stale timestamp, malformed header), and stay
 * disabled with no secret configured.
 */
class WorkosWebhookVerifierTest {

    private static final String SECRET = "whsec_test_0123456789";
    private static final long NOW = 1_700_000_000L;

    private static String signatureHeader(String secret, long ts, byte[] body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        mac.update((ts + ".").getBytes(StandardCharsets.UTF_8));
        mac.update(body);
        StringBuilder hex = new StringBuilder();
        for (byte b : mac.doFinal()) {
            hex.append(String.format("%02x", b));
        }
        return "t=" + ts + ", v1=" + hex;
    }

    @Test
    void validSignatureIsAccepted() throws Exception {
        WorkosWebhookVerifier v = new WorkosWebhookVerifier(SECRET);
        byte[] body = "{\"event\":\"user.deleted\"}".getBytes(StandardCharsets.UTF_8);
        assertTrue(v.isEnabled());
        assertTrue(v.verify(signatureHeader(SECRET, NOW, body), body, NOW));
    }

    @Test
    void tamperedBodyIsRejected() throws Exception {
        WorkosWebhookVerifier v = new WorkosWebhookVerifier(SECRET);
        byte[] signed = "{\"event\":\"user.deleted\"}".getBytes(StandardCharsets.UTF_8);
        byte[] tampered = "{\"event\":\"user.updated\"}".getBytes(StandardCharsets.UTF_8);
        assertFalse(v.verify(signatureHeader(SECRET, NOW, signed), tampered, NOW));
    }

    @Test
    void wrongSecretIsRejected() throws Exception {
        WorkosWebhookVerifier v = new WorkosWebhookVerifier(SECRET);
        byte[] body = "{\"event\":\"user.deleted\"}".getBytes(StandardCharsets.UTF_8);
        assertFalse(v.verify(signatureHeader("whsec_attacker", NOW, body), body, NOW));
    }

    @Test
    void staleTimestampIsRejected() throws Exception {
        WorkosWebhookVerifier v = new WorkosWebhookVerifier(SECRET);
        byte[] body = "{\"event\":\"user.deleted\"}".getBytes(StandardCharsets.UTF_8);
        // Correctly signed, but 10 minutes old — outside the replay window.
        String header = signatureHeader(SECRET, NOW - 600, body);
        assertFalse(v.verify(header, body, NOW));
    }

    @Test
    void malformedHeaderIsRejected() {
        WorkosWebhookVerifier v = new WorkosWebhookVerifier(SECRET);
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        assertFalse(v.verify("garbage", body, NOW));
        assertFalse(v.verify(null, body, NOW));
        assertFalse(v.verify("t=abc, v1=zz", body, NOW));
    }

    @Test
    void disabledWithoutSecret() {
        WorkosWebhookVerifier v = new WorkosWebhookVerifier("");
        assertFalse(v.isEnabled());
        assertFalse(v.verify("t=1, v1=deadbeef", "{}".getBytes(StandardCharsets.UTF_8), NOW));
    }
}
