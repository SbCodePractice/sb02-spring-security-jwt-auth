package com.sb02.practice.security.config;

import io.jsonwebtoken.security.Keys;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Configuration
public class JwtConfig {

    /**
     * JWT 서명을 위한 SecretKey를 생성한다.
     * HMAC SHA 알고리즘을 위해서는 최소 32바이트 길이의 키가 필요하다.
     */
    @Bean
    public SecretKey jwtSecretKey(JwtProperties jwtProperties) {
        return Keys.hmacShaKeyFor(jwtProperties.secret().getBytes(StandardCharsets.UTF_8));
    }
}