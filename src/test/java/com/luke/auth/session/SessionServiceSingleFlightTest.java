package com.luke.auth.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.luke.auth.config.GatewayKeys;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

/**
 * #34: concurrent misses (and concurrent {@code fresh=true} bypasses) for the same
 * (user, tenant) must collapse into a SINGLE upstream computation — no cache stampede.
 *
 * <p>The mocked {@code corePermissions} blocks the leader inside the upstream call while
 * the other threads pile up on the single-flight future, so the assertion "upstream ran
 * once" is exercised under real contention rather than by luck.
 */
class SessionServiceSingleFlightTest {

    private static final int THREADS = 16;

    private record Fixture(SessionService svc, AtomicInteger coreCalls,
                           CountDownLatch leaderInside, CountDownLatch release,
                           SimpleMeterRegistry registry) {}

    private Fixture newFixture() {
        GatewayKeys keys = mock(GatewayKeys.class);
        PermissionsClient pc = mock(PermissionsClient.class);
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        AtomicInteger coreCalls = new AtomicInteger();
        CountDownLatch leaderInside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        Map<String, Object> core = new HashMap<>();
        core.put("tenants", List.of("A", "B"));
        core.put("operator", false);
        core.put("roles", Map.of());

        try {
            when(keys.mintActAsToken(anyString())).thenReturn("act");
            when(pc.capabilities(anyString(), anyString(), anyString())).thenReturn(Map.of());
            when(pc.corePermissions("act")).thenAnswer(inv -> {
                coreCalls.incrementAndGet();
                leaderInside.countDown();     // signal the leader has entered the upstream call
                release.await(5, TimeUnit.SECONDS); // hold here while followers pile up
                return core;
            });
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return new Fixture(new SessionService(keys, pc, 60, 10_000, registry),
                coreCalls, leaderInside, release, registry);
    }

    private double loadCount(SimpleMeterRegistry r) {
        return r.get("auth.session.upstream.loads").counter().count();
    }

    @Test
    void concurrentMissesCollapseToOneUpstreamComputation() throws Exception {
        assertSingleFlight(false);
    }

    /** fresh=true bypasses the cache read but must still be coalesced — no fresh-storm abuse. */
    @Test
    void concurrentFreshBypassesAreCoalesced() throws Exception {
        assertSingleFlight(true);
    }

    private void assertSingleFlight(boolean bypass) throws Exception {
        Fixture f = newFixture();
        ExecutorService pool = Executors.newFixedThreadPool(THREADS);
        CyclicBarrier startTogether = new CyclicBarrier(THREADS);
        try {
            List<Future<Map<String, Object>>> futures = IntStream.range(0, THREADS)
                    .mapToObj(i -> pool.submit(() -> {
                        startTogether.await();                    // all fire at once
                        return f.svc().session("user-1", "A", bypass);
                    }))
                    .toList();

            // Leader is now inside the upstream call; give the followers time to reach the
            // single-flight join, then let the leader finish.
            f.leaderInside().await(5, TimeUnit.SECONDS);
            Thread.sleep(300);
            f.release().countDown();

            for (Future<Map<String, Object>> fut : futures) {
                Map<String, Object> body = fut.get(5, TimeUnit.SECONDS);
                assertNotNull(body);
                assertEquals("user-1", body.get("userId"));
            }
        } finally {
            f.release().countDown(); // ensure the leader is never left blocked
            pool.shutdownNow();
            pool.awaitTermination(5, TimeUnit.SECONDS);
        }

        assertEquals(1, f.coreCalls().get(),
                THREADS + " concurrent requests must trigger exactly ONE upstream computation");
        assertEquals(1.0, loadCount(f.registry()), 0.0001, "the upstream-load metric must count one leader");
    }

    @Test
    void afterCompletionCacheServesWithoutNewUpstreamCall() throws Exception {
        Fixture f = newFixture();
        f.release().countDown(); // no blocking needed for the sequential path

        Map<String, Object> first = f.svc().session("user-1", "A", false);
        Map<String, Object> second = f.svc().session("user-1", "A", false); // cache hit
        assertNotNull(first);
        assertNotNull(second);
        assertEquals(1, f.coreCalls().get(), "second call must be served from cache");
        assertEquals(1.0, loadCount(f.registry()), 0.0001);
    }
}
