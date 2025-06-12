package com.sb02.practice.security.controller;

import com.sb02.practice.security.service.UserSecurityService;
import com.sb02.practice.security.util.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/user")
public class UserController {

    private final UserSecurityService userSecurityService;
    private final JwtUtil jwtUtil;

    public UserController(UserSecurityService userSecurityService, JwtUtil jwtUtil) {
        this.userSecurityService = userSecurityService;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 현재 인증된 사용자 정보 조회
     * 모든 인증된 사용자가 접근 가능
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "사용자 프로필 조회 성공",
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "timestamp", System.currentTimeMillis()
        ));
    }

    /**
     * 사용자별 개인 데이터 조회
     * JWT 토큰에서 사용자 정보를 추출하여 활용
     */
    @GetMapping("/data")
    public ResponseEntity<?> getUserData(Authentication authentication,
                                         @RequestHeader("Authorization") String authHeader) {
        // JWT 토큰에서 사용자 정보 추출
        String token = authHeader.substring(7); // "Bearer " 제거
        Long userId = jwtUtil.extractUserId(token);
        String email = jwtUtil.extractEmail(token);

        return ResponseEntity.ok(Map.of(
                "message", "개인 데이터를 조회하였습니다.",
                "username", authentication.getName(),
                "userId", userId,
                "email", email,
                "personalData", Map.of(
                        "preferences", Map.of("theme", "dark", "language", "ko"),
                        "lastLogin", "2024-12-04T10:30:00",
                        "activityScore", 85
                )
        ));
    }

    /**
     * 특정 사용자 정보 조회 (본인 정보만 조회 가능)
     * SpEL 표현식을 사용한 메서드 수준 보안 적용
     */
    @GetMapping("/{userId}")
    @PreAuthorize("@userSecurityService.isOwner(authentication.name, #userId)")
    public ResponseEntity<?> getUserById(@PathVariable Long userId, Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "사용자 정보를 조회하였습니다.",
                "userId", userId,
                "requestedBy", authentication.getName(),
                "userInfo", Map.of(
                        "id", userId,
                        "username", "user" + userId,
                        "email", "user" + userId + "@example.com"
                )
        ));
    }
}