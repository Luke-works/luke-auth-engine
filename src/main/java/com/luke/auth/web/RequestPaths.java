package com.luke.auth.web;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * One source of truth for request-path canonicalization and the public-surface rule (#29).
 *
 * <p>The gateway's public-vs-protected decision must be made on a <b>canonicalized</b> path —
 * percent-decoded and traversal-resolved — or a request like {@code /api/public/%2e%2e/me} would
 * look public while resolving to a protected endpoint downstream (the path-traversal advisory,
 * GHSA-hm7m). Both the central {@code SecurityFilterChain} allowlist and the proxy consult this,
 * so the security matcher and the forwarder can never disagree about what "public" means.
 */
public final class RequestPaths {

    private RequestPaths() {}

    /**
     * Decode percent-escapes and resolve segments to a canonical absolute path. Returns
     * {@code null} if the path is malformed or contains any traversal ({@code ..}) segment —
     * including encoded forms like {@code %2e%2e}.
     */
    public static String canonicalPath(String rawUri) {
        if (rawUri == null) {
            return null;
        }
        String decoded;
        try {
            decoded = URLDecoder.decode(rawUri, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
        Deque<String> segments = new ArrayDeque<>();
        for (String segment : decoded.split("/", -1)) {
            if (segment.isEmpty() || segment.equals(".")) {
                continue; // collapse empty ("//") and current-dir segments
            }
            if (segment.equals("..")) {
                return null; // refuse traversal outright
            }
            segments.addLast(segment);
        }
        return "/" + String.join("/", segments);
    }

    /**
     * True iff the <b>canonical</b> path is one of the gateway's unauthenticated proxy surfaces
     * (public embed API / page / assets). A traversing path (canonical == {@code null}) is never
     * public.
     */
    public static boolean isPublicProxyPath(String rawUri) {
        String c = canonicalPath(rawUri);
        return c != null
                && (c.startsWith("/api/public/") || c.startsWith("/embed/") || c.startsWith("/embed-assets/"));
    }
}
