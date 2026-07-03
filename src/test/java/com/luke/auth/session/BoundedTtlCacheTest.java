package com.luke.auth.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Guards the session-cache memory-leak fix (#22): the cache is size-capped and TTL'd. */
class BoundedTtlCacheTest {

    @Test
    void getReturnsValueWithinTtl() {
        BoundedTtlCache<String> c = new BoundedTtlCache<>(10, 60_000);
        c.put("k", "v");
        assertEquals("v", c.get("k"));
    }

    @Test
    void missingKeyReturnsNull() {
        assertNull(new BoundedTtlCache<String>(10, 60_000).get("nope"));
    }

    @Test
    void expiredEntryReturnsNullAndIsDropped() {
        BoundedTtlCache<String> c = new BoundedTtlCache<>(10, 0); // TTL 0 → already expired
        c.put("k", "v");
        assertNull(c.get("k"));
        assertEquals(0, c.size());
    }

    @Test
    void invalidatePrefixDropsOnlyMatchingKeys() {
        BoundedTtlCache<String> c = new BoundedTtlCache<>(10, 60_000);
        c.put("user|A", "1");
        c.put("user|B", "2");
        c.put("other|A", "3");
        c.invalidatePrefix("user|");
        assertNull(c.get("user|A"));
        assertNull(c.get("user|B"));
        assertEquals("3", c.get("other|A"));
    }

    @Test
    void sizeNeverExceedsTheCap() {
        BoundedTtlCache<String> c = new BoundedTtlCache<>(3, 60_000);
        for (int i = 0; i < 1_000; i++) {
            c.put("k" + i, "v" + i);
        }
        assertTrue(c.size() <= 3, "cache grew past its cap: " + c.size());
    }
}
