package com.luke.auth.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.luke.auth.web.RedisRateLimitStore.WindowCounter;
import io.lettuce.core.RedisClient;
import io.lettuce.core.ScriptOutputType;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import redis.embedded.RedisServer;

/**
 * #56: proves the shared limiter against a REAL Redis (embedded — no Docker) — including the
 * point of the whole thing: two SEPARATE store instances (standing in for two gateway replicas)
 * share one global limit. Skips gracefully if embedded Redis can't start on this platform; it
 * runs in CI (linux/x64).
 */
class RedisRateLimitIntegrationTest {

    private static final int PORT = 16399;
    private static final String INCR_EXPIRE =
            "local c = redis.call('INCR', KEYS[1]) "
            + "if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end "
            + "return c";

    private static RedisServer server;

    @BeforeAll
    static void startRedis() {
        try {
            server = new RedisServer(PORT);
            server.start();
        } catch (Exception e) {
            server = null; // embedded redis unavailable on this platform → tests skip
        }
    }

    @AfterAll
    static void stopRedis() {
        if (server != null) {
            try { server.stop(); } catch (Exception ignore) { /* best effort */ }
        }
    }

    private WindowCounter counterOn(RedisCommands<String, String> sync) {
        return (bucketKey, wm) ->
                (Long) sync.eval(INCR_EXPIRE, ScriptOutputType.INTEGER, new String[] {bucketKey}, String.valueOf(wm));
    }

    @Test
    void realRedisEnforcesTheLimitAndSharesItAcrossInstances() {
        assumeTrue(server != null, "embedded Redis not available on this platform");

        RedisClient client = RedisClient.create("redis://localhost:" + PORT);
        try (StatefulRedisConnection<String, String> connA = client.connect();
             StatefulRedisConnection<String, String> connB = client.connect()) {

            RateLimitStore fallback = new RateLimiter(1000, 60_000, 100);
            // Two independent store instances → two "replicas" pointing at the same Redis.
            RedisRateLimitStore replicaA = new RedisRateLimitStore(2, 60_000, counterOn(connA.sync()), fallback);
            RedisRateLimitStore replicaB = new RedisRateLimitStore(2, 60_000, counterOn(connB.sync()), fallback);

            long now = 1_700_000_000_000L;
            String key = "itest|/auth/login";

            assertEquals(-1, replicaA.retryAfterSeconds(key, now), "1st hit (on A) allowed");
            assertEquals(-1, replicaB.retryAfterSeconds(key, now), "2nd hit (on B) allowed — shared count = 2");
            // The 3rd hit is over the GLOBAL max of 2, regardless of which replica serves it.
            assertTrue(replicaA.retryAfterSeconds(key, now) >= 1, "3rd hit limited on A (shared)");
            assertTrue(replicaB.retryAfterSeconds(key, now) >= 1, "and limited on B (shared)");

            // A different key is independent.
            assertEquals(-1, replicaA.retryAfterSeconds("other|/auth/login", now));
        } finally {
            client.shutdown();
        }
    }
}
