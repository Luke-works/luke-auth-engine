package com.luke.auth.config;

import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Defense-in-depth for the dev-mode auth backdoors (#43). Dev-mode enables
 * authenticate-as-anyone shortcuts ({@code X-Dev-User}, {@code /dev/token}); a
 * single misconfigured {@code LUKE_AUTH_DEV_MODE=true} in a shared/prod environment
 * would otherwise be full impersonation. This guard requires a SECOND, independent
 * control — the {@code dev} Spring profile — so the backdoors can never be enabled
 * by one env var alone, and fails the app fast otherwise.
 */
@Component
public class DevModeGuard {

    private static final Logger log = LoggerFactory.getLogger(DevModeGuard.class);

    public DevModeGuard(@Value("${luke.auth.dev-mode:false}") boolean devMode, Environment env) {
        if (!devMode) {
            return;
        }
        boolean devProfile = Arrays.asList(env.getActiveProfiles()).contains("dev");
        if (!devProfile) {
            throw new IllegalStateException(
                    "luke.auth.dev-mode=true requires the 'dev' Spring profile (set SPRING_PROFILES_ACTIVE=dev). "
                    + "Dev-mode enables auth backdoors (X-Dev-User header, /dev/token) and must never run under a "
                    + "production profile.");
        }
        log.warn("============================================================");
        log.warn("DEV-MODE ENABLED — auth backdoors are active (X-Dev-User, /dev/token).");
        log.warn("This is LOCAL-ONLY. Never enable in a shared or production environment.");
        log.warn("============================================================");
    }
}
