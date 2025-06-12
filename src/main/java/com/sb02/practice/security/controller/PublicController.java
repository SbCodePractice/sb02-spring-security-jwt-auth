package com.sb02.practice.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/public")
public class PublicController {

    /**
     * 공개 API - 인증 불필요
     */
    @GetMapping("/status")
    public ResponseEntity<?> getPublicStatus() {
        return ResponseEntity.ok(Map.of(
                "message", "시스템이 정상 작동 중입니다.",
                "timestamp", System.currentTimeMillis(),
                "version", "1.0.0"
        ));
    }
}
