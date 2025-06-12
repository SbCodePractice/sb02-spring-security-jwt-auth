package com.sb02.practice.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/manager")
public class ManagerController {

    /**
     * 매니저 대시보드 (매니저 이상 권한)
     * URL 기반 권한 설정으로 접근 제어됨
     */
    @GetMapping("/dashboard")
    public ResponseEntity<?> getManagerDashboard(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
                "message", "매니저 대시보드에 접근하였습니다.",
                "user", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "teamStats", Map.of(
                        "teamMembers", 25,
                        "completedTasks", 45,
                        "pendingTasks", 12
                )
        ));
    }

    /**
     * 팀원 관리 (매니저 이상 권한)
     * 메서드 수준 보안으로 추가 권한 검사
     */
    @GetMapping("/team")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<?> getTeamMembers() {
        return ResponseEntity.ok(Map.of(
                "message", "팀원 목록을 조회하였습니다.",
                "teamMembers", List.of(
                        Map.of("id", 4, "name", "김팀원", "position", "개발자"),
                        Map.of("id", 5, "name", "이팀원", "position", "디자이너"),
                        Map.of("id", 6, "name", "박팀원", "position", "기획자")
                )
        ));
    }

    /**
     * 팀 보고서 생성 (매니저 이상 권한)
     */
    @PostMapping("/reports")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<?> generateReport(@RequestBody Map<String, Object> reportRequest) {
        return ResponseEntity.ok(Map.of(
                "message", "팀 보고서가 생성되었습니다.",
                "reportId", "RPT-" + System.currentTimeMillis(),
                "requestData", reportRequest
        ));
    }
}