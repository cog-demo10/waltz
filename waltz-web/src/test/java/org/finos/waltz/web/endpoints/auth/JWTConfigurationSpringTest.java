package org.finos.waltz.web.endpoints.auth;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class JWTConfigurationSpringTest {

    @Configuration
    static class Cfg {
        @Bean
        static PropertySourcesPlaceholderConfigurer pspc() { return new PropertySourcesPlaceholderConfigurer(); }
    }

    @Test
    public void beanIsCreatedFromSystemProperty() {
        System.setProperty("waltz.jwt.secret", "0123456789abcdef0123456789abcdef0123456789abcdef");
        try (AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext(Cfg.class, JWTConfiguration.class)) {
            assertNotNull(ctx.getBean(JWTConfiguration.class).hmac512());
        } finally {
            System.clearProperty("waltz.jwt.secret");
        }
    }
}
