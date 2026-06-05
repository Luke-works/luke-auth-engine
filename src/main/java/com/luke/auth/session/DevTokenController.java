package com.luke.auth.session;

import com.luke.auth.config.GatewayKeys;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Dev-only: mints an act-as token for a given engine userId so downstream
 * resource servers (e.g. capability-engine) can be exercised locally without a
 * real Clerk login. Returns 404 unless {@code luke.auth.dev-mode=true}.
 *
 * <p>NEVER enable dev-mode in shared/prod environments — this hands out
 * act-as-anyone tokens.
 */
@RestController
public class DevTokenController {

    private final GatewayKeys gatewayKeys;
    private final boolean devMode;

    public DevTokenController(GatewayKeys gatewayKeys, @Value("${luke.auth.dev-mode:false}") boolean devMode) {
        this.gatewayKeys = gatewayKeys;
        this.devMode = devMode;
    }

    @GetMapping("/dev/token")
    public ResponseEntity<?> token(@RequestParam String user) throws Exception {
        if (!devMode) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "Not Found"));
        }
        return ResponseEntity.ok(Map.of("token", gatewayKeys.mintActAsToken(user)));
    }
}
