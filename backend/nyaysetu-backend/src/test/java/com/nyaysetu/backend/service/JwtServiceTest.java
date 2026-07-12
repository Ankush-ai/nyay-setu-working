package com.nyaysetu.backend.service;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String TEST_SECRET =
            "test-secret-key-minimum-256-bits-required-for-tests-only";

    private JwtService jwtService;
    private UserDetails userDetails;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();

        userDetails = User.withUsername("user@example.com")
                .password("password")
                .authorities("ROLE_USER")
                .build();

        ReflectionTestUtils.setField(jwtService, "secretKey", TEST_SECRET);
    }

    @Test
    void generateToken_shouldUseConfiguredExpiration() {
        long configuredExpirationMs = 120_000L;
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", configuredExpirationMs);

        String token = jwtService.generateToken(Map.of(), userDetails);

        Date issuedAt = jwtService.extractClaim(token, Claims::getIssuedAt);
        Date expiration = jwtService.extractClaim(token, Claims::getExpiration);

        assertThat(expiration.getTime() - issuedAt.getTime())
                .isEqualTo(configuredExpirationMs);
    }

    @Test
    void validateJwtExpirationConfiguration_shouldRejectNonPositiveExpiration() {
        ReflectionTestUtils.setField(jwtService, "jwtExpirationMs", 0L);

        assertThatThrownBy(() -> jwtService.validateJwtExpirationConfiguration())
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("jwt.expiration must be greater than 0 milliseconds");
    }
}