package com.luke.auth.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntUnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Guards the upstream-resilience fix (#23): {@link PermissionsClient} retries
 * transient failures (network / 5xx) but never retries a deterministic 4xx.
 * Uses a tiny in-process HTTP server (JDK built-in, no deps).
 */
class PermissionsClientRetryTest {

    private HttpServer server;
    private final AtomicInteger hits = new AtomicInteger();

    private String startServer(IntUnaryOperator statusForHit, String okBody) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/me/permissions", ex -> {
            int n = hits.incrementAndGet();
            int status = statusForHit.applyAsInt(n);
            byte[] body = (status / 100 == 2 ? okBody : "{}").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, body.length);
            ex.getResponseBody().write(body);
            ex.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    private PermissionsClient client(String base) {
        return new PermissionsClient(base, 3, 1); // 3 attempts, 1ms backoff
    }

    @Test
    void retriesOn5xxThenSucceeds() throws Exception {
        String base = startServer(n -> n < 2 ? 503 : 200, "{\"operator\":true}");
        var result = client(base).corePermissions("tok");
        assertEquals(Boolean.TRUE, result.get("operator"));
        assertEquals(2, hits.get(), "should have retried once after the 503");
    }

    @Test
    void doesNotRetryOn4xx() throws Exception {
        String base = startServer(n -> 403, "{}");
        PermissionsClient.UpstreamException ex = assertThrows(
                PermissionsClient.UpstreamException.class, () -> client(base).corePermissions("tok"));
        assertEquals(403, ex.status());
        assertEquals(1, hits.get(), "4xx must not be retried");
    }

    @Test
    void givesUpAfterMaxAttemptsOn5xx() throws Exception {
        String base = startServer(n -> 503, "{}");
        PermissionsClient.UpstreamException ex = assertThrows(
                PermissionsClient.UpstreamException.class, () -> client(base).corePermissions("tok"));
        assertEquals(503, ex.status());
        assertEquals(3, hits.get(), "should stop at maxAttempts");
    }
}
