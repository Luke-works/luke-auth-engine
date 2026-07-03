package com.luke.auth.workos;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * #32: auto-verifying email at registration is a dev-only shortcut. The app must
 * refuse to boot with it enabled unless dev-mode is on, so it can't reach prod.
 */
class WorkosClientGuardTest {

    private WorkosClient build(boolean markVerified, boolean devMode) {
        return new WorkosClient(
                "https://api.workos.com", "client", "key", "http://localhost/cb", markVerified, devMode);
    }

    @Test
    void refusesAutoVerifyWithoutDevMode() {
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> build(true, false));
        org.junit.jupiter.api.Assertions.assertTrue(ex.getMessage().toLowerCase().contains("production"));
    }

    @Test
    void allowsAutoVerifyInDevMode() {
        assertDoesNotThrow(() -> build(true, true));
    }

    @Test
    void defaultProdConfigBootsFine() {
        assertDoesNotThrow(() -> build(false, false));
    }
}
