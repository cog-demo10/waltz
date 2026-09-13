/*
 * Waltz - Enterprise Architecture
 * Copyright (C) 2016, 2017, 2018, 2019 Waltz open source project
 * See README.md for more information
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific
 *
 */

package org.finos.waltz.web.endpoints.auth;

import com.auth0.jwt.algorithms.Algorithm;
import org.finos.waltz.common.StringUtilities;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Holds the per-deployment HMAC key used to sign and verify Waltz issued JWT tokens.
 * <p>
 * The key is read from the {@code waltz.jwt.secret} property (waltz.properties / JNDI / system property),
 * falling back to the {@code WALTZ_JWT_SECRET} environment variable.  Startup fails if neither is
 * present or the key is too short.
 */
@Component
public class JWTConfiguration {

    public static final String ISSUER = "Waltz";
    public static final String PROPERTY_NAME = "waltz.jwt.secret";
    public static final String ENV_VAR_NAME = "WALTZ_JWT_SECRET";
    public static final int MIN_SECRET_BYTES = 32;

    private final byte[] secret;


    @Autowired
    public JWTConfiguration(@Value("${" + PROPERTY_NAME + ":#{null}}") String configuredSecret) {
        this(configuredSecret, System.getenv(ENV_VAR_NAME));
    }


    JWTConfiguration(String configuredSecret, String envSecret) {
        String resolved = StringUtilities.notEmpty(configuredSecret)
                ? configuredSecret
                : envSecret;

        if (StringUtilities.isEmpty(resolved)) {
            throw new IllegalStateException(String.format(
                    "No JWT signing secret configured. Set the '%s' property or the '%s' environment variable to a random value of at least %d bytes",
                    PROPERTY_NAME,
                    ENV_VAR_NAME,
                    MIN_SECRET_BYTES));
        }

        byte[] bytes = resolved.trim().getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException(String.format(
                    "JWT signing secret is too short (%d bytes), it must be at least %d bytes",
                    bytes.length,
                    MIN_SECRET_BYTES));
        }

        this.secret = bytes;
    }


    public Algorithm hmac256() {
        return Algorithm.HMAC256(secret);
    }


    public Algorithm hmac512() {
        return Algorithm.HMAC512(secret);
    }

}
