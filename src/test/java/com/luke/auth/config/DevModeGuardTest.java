package com.luke.auth.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/**
 * #43: dev-mode (auth backdoors) needs a SECOND control — the 'dev' profile — so a
 * single LUKE_AUTH_DEV_MODE=true can't open impersonation in a prod profile.
 */
class DevModeGuardTest {

    @Test
    void devModeWithoutDevProfileFailsFast() {
        IllegalStateException ex =
                assertThrows(IllegalStateException.class, () -> new DevModeGuard(true, new MockEnvironment()));
        org.junit.jupiter.api.Assertions.assertTrue(ex.getMessage().contains("dev"));
    }

    @Test
    void devModeWithDevProfileBoots() {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles("dev");
        assertDoesNotThrow(() -> new DevModeGuard(true, env));
    }

    @Test
    void devModeOffBootsUnderAnyProfile() {
        assertDoesNotThrow(() -> new DevModeGuard(false, new MockEnvironment()));
    }
}
