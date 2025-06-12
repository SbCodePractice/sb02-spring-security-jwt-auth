package com.sb02.practice.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    /**
     * 관리자 전용 대시보드
     * URL 기반 권한 설정으로 ADMIN 역할만 접근 가능
     */
    @GetMapping("/dashboard")
    public ResponseEntity<?> getAdminDashboard(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "관리자 대시보드에 접근하였습니다.",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "systemStats", Map.of(
                        "totalUsers", 150,
                        "activeUsers", 120,
                        "systemHealth", "정상",
                        "memoryUsage", "65%",
                        "cpuUsage", "23%"
                )
        ));
    }

    /**
     * 전체 사용자 관리 (관리자만 접근 가능)
     */
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(Map.of(
                "message", "전체 사용자 목록을 조회하였습니다.",
                "users", List.of(
                        Map.of("id", 1, "username", "admin", "role", "ADMIN", "status", "활성"),
                        Map.of("id", 2, "username", "user", "role", "USER", "status", "활성"),
                        Map.of("id", 3, "username", "manager", "role", "MANAGER", "status", "활성")
                ),
                "totalCount", 3
        ));
    }

    /**
     * 시스템 설정 관리 (관리자만 접근 가능)
     */
    @PostMapping("/settings")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateSystemSettings(@RequestBody Map<String, Object> settings) {
        return ResponseEntity.ok(Map.of(
                "message", "시스템 설정이 업데이트되었습니다.",
                "settings", settings,
                "timestamp", System.currentTimeMillis()
        ));
    }

    /**
     * 사용자 권한 변경 (관리자만 접근 가능)
     */
    @PutMapping("/users/{userId}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> changeUserRole(@PathVariable Long userId,
                                            @RequestBody Map<String, String> roleRequest) {
        String newRole = roleRequest.get("role");
        return ResponseEntity.ok(Map.of(
                "message", "사용자 권한이 변경되었습니다.",
                "userId", userId,
                "newRole", newRole,
                "timestamp", System.currentTimeMillis()
        ));
    }
}