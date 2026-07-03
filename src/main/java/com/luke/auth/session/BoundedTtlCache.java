package com.luke.auth.session;

import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A small thread-safe cache with a hard size cap and a per-entry TTL.
 *
 * <p>The session cache previously used a plain {@link ConcurrentHashMap} whose
 * entries were only expired on read of the same key and never evicted, so it grew
 * without bound (one entry per (user, tenant) forever) — a slow memory leak. This
 * caps total entries and drops expired/oldest ones when full.
 */
class BoundedTtlCache<V> {

    private record Entry<V>(V value, long expiresAt) {}

    private final Map<String, Entry<V>> map = new ConcurrentHashMap<>();
    private final int maxEntries;
    private final long ttlMillis;

    BoundedTtlCache(int maxEntries, long ttlMillis) {
        this.maxEntries = Math.max(1, maxEntries);
        this.ttlMillis = ttlMillis;
    }

    /** Returns the live value, or {@code null} if missing or expired. */
    V get(String key) {
        Entry<V> e = map.get(key);
        if (e == null) {
            return null;
        }
        if (e.expiresAt() <= System.currentTimeMillis()) {
            map.remove(key, e); // drop the stale entry
            return null;
        }
        return e.value();
    }

    /** Store a value with a fresh TTL, evicting if the cache is at capacity. */
    void put(String key, V value) {
        if (map.size() >= maxEntries && !map.containsKey(key)) {
            evict();
        }
        map.put(key, new Entry<>(value, System.currentTimeMillis() + ttlMillis));
    }

    int size() {
        return map.size();
    }

    /** Drop every entry whose key starts with {@code prefix} (e.g. all of a user's
     *  per-tenant session entries). Used to invalidate a session on logout/delete. */
    void invalidatePrefix(String prefix) {
        map.keySet().removeIf(k -> k.startsWith(prefix));
    }

    /** Drop expired entries first, then the soonest-to-expire until under the cap. */
    private void evict() {
        long now = System.currentTimeMillis();
        map.entrySet().removeIf(e -> e.getValue().expiresAt() <= now);
        while (map.size() >= maxEntries) {
            map.entrySet().stream()
                    .min(Comparator.comparingLong(e -> e.getValue().expiresAt()))
                    .map(Map.Entry::getKey)
                    .ifPresent(map::remove);
        }
    }
}
