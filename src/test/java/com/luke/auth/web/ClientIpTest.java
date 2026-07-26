package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * The client-IP resolution behind the rate limiter + audit source IP. X-Forwarded-For is
 * client-authored on the left, so with N trusted proxies the real client is the Nth entry from the
 * RIGHT. This fleet runs behind Cloudflare + Render (2 hops, verified empirically).
 */
class ClientIpTest {

    private MockHttpServletRequest req(String xff, String remote) {
        MockHttpServletRequest r = new MockHttpServletRequest();
        if (xff != null) {
            r.addHeader("X-Forwarded-For", xff);
        }
        r.setRemoteAddr(remote);
        return r;
    }

    @Test
    void twoTrustedHops_ignoreSpoofedLeftmost() {
        // Chain the app sees with a spoof attempt: [spoofed, REAL-CLIENT, cloudflare].
        assertEquals("203.0.113.5",
                ClientIp.resolve(req("6.6.6.6, 203.0.113.5, 172.70.0.1", "10.0.0.9"), 2));
        // Normal (no spoof): [REAL-CLIENT, cloudflare].
        assertEquals("203.0.113.5",
                ClientIp.resolve(req("203.0.113.5, 172.70.0.1", "10.0.0.9"), 2));
    }

    @Test
    void spoofRotationDoesNotChangeTheResolvedIp() {
        String a = ClientIp.resolve(req("6.6.6.6, 203.0.113.5, 172.70.0.1", "10.0.0.9"), 2);
        String b = ClientIp.resolve(req("9.9.9.9, 203.0.113.5, 172.70.0.1", "10.0.0.9"), 2);
        assertEquals(a, b); // rotating the fake leftmost yields the same bucket — bypass closed
    }

    @Test
    void legacyZeroHops_keepsLeftmost() {
        assertEquals("203.0.113.5", ClientIp.resolve(req("203.0.113.5, 10.0.0.1", "10.0.0.9"), 0));
    }

    @Test
    void noForwardedFor_fallsBackToRemoteAddr() {
        assertEquals("10.0.0.9", ClientIp.resolve(req(null, "10.0.0.9"), 2));
    }

    @Test
    void clampsWhenConfiguredHopsExceedTheChain() {
        // Configured for 2 hops but only one entry present → clamp to leftmost, never index out of range.
        assertEquals("203.0.113.5", ClientIp.resolve(req("203.0.113.5", "10.0.0.9"), 2));
    }
}
