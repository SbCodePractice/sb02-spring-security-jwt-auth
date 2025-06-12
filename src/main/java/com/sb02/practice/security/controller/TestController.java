package com.sb02.practice.security.controller;

import com.sb02.practice.security.util.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/test")
public class TestController {

    private final JwtUtil jwtUtil;

    public TestController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    /**
     * 토큰 정보 확인 API
     * 현재 사용 중인 JWT 토큰의 상세 정보를 반환
     */
    @GetMapping("/token-info")
    public ResponseEntity<?> getTokenInfo(@RequestHeader("Authorization") String authHeader,
                                          Authentication authentication) {
        String token = authHeader.substring(7);

        return ResponseEntity.ok(Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "tokenExpired", jwtUtil.isTokenExpired(token),
                "issuedAt", jwtUtil.extractIssuedAt(token),
                "expiration", jwtUtil.extractExpiration(token),
                "currentTime", System.currentTimeMillis(),
                "tokenClaims", Map.of(
                        "role", jwtUtil.extractRole(token),
                        "email", jwtUtil.extractEmail(token),
                        "userId", jwtUtil.extractUserId(token)
                )
        ));
    }

    /**
     * 보호된 리소스 (토큰 검증 테스트용)
     */
    @GetMapping("/protected")
    public ResponseEntity<?> getProtectedResource(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "보호된 리소스에 성공적으로 접근했습니다.",
                "user", authentication.getName(),
                "timestamp", System.currentTimeMillis()
        ));
    }
}
