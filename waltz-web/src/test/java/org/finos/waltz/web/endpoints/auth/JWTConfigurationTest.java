package org.finos.waltz.web.endpoints.auth;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JWTConfigurationTest {

    private static final String STRONG_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef";


    @Test
    public void failsWhenNoSecretConfigured() {
        assertThrows(IllegalStateException.class, () -> new JWTConfiguration(null, null));
        assertThrows(IllegalStateException.class, () -> new JWTConfiguration("", ""));
    }


    @Test
    public void failsWhenSecretTooShort() {
        assertThrows(IllegalStateException.class, () -> new JWTConfiguration("secret", null));
    }


    @Test
    public void propertyTakesPrecedenceOverEnvironment() {
        JWTConfiguration fromProperty = new JWTConfiguration(STRONG_SECRET, "x".repeat(40));
        JWTConfiguration fromEnv = new JWTConfiguration(null, STRONG_SECRET);

        String token = JWT.create()
                .withIssuer(JWTConfiguration.ISSUER)
                .withSubject("bob")
                .sign(fromProperty.hmac512());

        assertEquals("bob", JWT.require(fromEnv.hmac512()).build().verify(token).getSubject());
    }


    @Test
    public void tokensSignedWithTheOldDefaultSecretAreRejected() {
        JWTConfiguration config = new JWTConfiguration(STRONG_SECRET, null);

        String forged = JWT.create()
                .withIssuer(JWTConfiguration.ISSUER)
                .withSubject("admin")
                .sign(com.auth0.jwt.algorithms.Algorithm.HMAC512("secret"));

        assertThrows(SignatureVerificationException.class,
                () -> JWT.require(config.hmac512()).build().verify(forged));
    }

}
