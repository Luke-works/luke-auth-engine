package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/**
 * Prod fail-fast: the gateway must not boot in a hardened posture unless strict token
 * validation AND a stable signing key are both enabled. Mirrors {@link DevModeGuardTest}.
 */
class AuthHardeningGuardTest {

    @Test
    void devWithoutHardeningBootsRegardlessOfFlags() {
        // No 'prod' profile and require-hardened=false → never throws (local/dev posture).
        assertDoesNotThrow(() -> new AuthHardeningGuard(false, false, false, new MockEnvironment()));
    }

    @Test
    void prodProfileWithLenientFlagsFailsFast() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(false, false, false, env));
        assertTrue(ex.getMessage().contains("strict-validation"));
        assertTrue(ex.getMessage().contains("require-stable-key"));
    }

    @Test
    void requireHardenedFlagAloneFailsFastWhenLenient() {
        // require-hardened=true forces the check even without the prod profile.
        assertThrows(IllegalStateException.class,
                () -> new AuthHardeningGuard(false, true, true, new MockEnvironment()));
    }

    @Test
    void prodProfileWithBothEnabledBoots() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("prod");
        assertDoesNotThrow(() -> new AuthHardeningGuard(true, true, false, env));
    }
}
