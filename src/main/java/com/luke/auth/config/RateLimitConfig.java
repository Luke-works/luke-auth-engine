package com.luke.auth.config;

import com.luke.auth.web.RateLimitStore;
import com.luke.auth.web.RateLimiter;
import com.luke.auth.web.RedisRateLimitStore;
import io.lettuce.core.RedisClient;
import io.lettuce.core.ScriptOutputType;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

/**
 * Chooses the rate-limit backing store (#56): a shared Redis limiter when {@code REDIS_URL} is
 * configured, else the in-memory per-instance {@link RateLimiter}.
 *
 * <p><b>Default-lenient:</b> with no {@code REDIS_URL} (dev/qa) the in-memory limiter is used. If
 * {@code REDIS_URL} is set but Redis is unreachable at startup, the app still boots on the
 * in-memory limiter (logged loudly) rather than failing — a rate limiter must never take the
 * gateway down.
 */
@Configuration
public class RateLimitConfig {

    private static final Logger log = LoggerFactory.getLogger(RateLimitConfig.class);

    /** Atomic INCR + first-hit PEXPIRE, so a counted window always has a TTL (no leak). */
    private static final String INCR_EXPIRE =
            "local c = redis.call('INCR', KEYS[1]) "
            + "if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end "
            + "return c";

    @Bean
    RateLimitStore rateLimitStore(
            @Value("${luke.auth.ratelimit.max-requests:10}") int maxRequests,
            @Value("${luke.auth.ratelimit.window-seconds:60}") long windowSeconds,
            @Value("${luke.auth.ratelimit.max-keys:50000}") int maxKeys,
            @Value("${luke.auth.ratelimit.redis-url:}") String redisUrl) {

        long windowMillis = windowSeconds * 1000;
        RateLimiter inMemory = new RateLimiter(maxRequests, windowMillis, maxKeys);

        if (!StringUtils.hasText(redisUrl)) {
            log.info("Rate limiter: in-memory (per-instance). Set REDIS_URL for a global "
                    + "cross-instance limit under horizontal scale-out.");
            return inMemory;
        }

        RedisClient client = null;
        try {
            client = RedisClient.create(redisUrl);
            StatefulRedisConnection<String, String> conn = client.connect(); // validates connectivity
            RedisCommands<String, String> sync = conn.sync();
            RedisClient created = client;
            RedisRateLimitStore.WindowCounter counter = (bucketKey, wm) ->
                    (Long) sync.eval(INCR_EXPIRE, ScriptOutputType.INTEGER,
                            new String[] {bucketKey}, String.valueOf(wm));
            log.info("Rate limiter: Redis-backed GLOBAL limiter via REDIS_URL.");
            return new RedisRateLimitStore(maxRequests, windowMillis, counter, inMemory,
                    conn, created::shutdown);
        } catch (Exception e) {
            log.error("REDIS_URL is set but Redis is unavailable at startup — falling back to the "
                    + "in-memory (per-instance) limiter. The app still serves; fix Redis to restore "
                    + "the global limit.", e);
            if (client != null) {
                try { client.shutdown(); } catch (Exception ignore) { /* best effort */ }
            }
            return inMemory;
        }
    }
}
