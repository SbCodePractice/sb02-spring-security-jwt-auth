package com.sb02.practice.security.controller;

import com.sb02.practice.security.dto.LoginRequest;
import com.sb02.practice.security.dto.RegisterRequest;
import com.sb02.practice.security.entity.User;
import com.sb02.practice.security.service.UserService;
import com.sb02.practice.security.util.JwtUtil;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager,
                          UserService userService,
                          JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    /**
     * 사용자 로그인 API
     *
     * @param loginRequest 로그인 요청 정보 (사용자명, 비밀번호)
     * @return JWT 토큰과 사용자 정보
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            // Spring Security의 AuthenticationManager를 통한 인증
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            // 인증 성공 시 사용자 정보 조회
            User user = userService.findByUsername(loginRequest.getUsername());

            // JWT Access Token 생성 (사용자 정보 포함)
            Map<String, Object> claims = Map.of(
                    "role", user.getRole().name(),
                    "email", user.getEmail(),
                    "userId", user.getId()
            );

            String accessToken = jwtUtil.generateAccessToken(user.getUsername(), claims);

            // 성공 응답 생성
            Map<String, Object> response = Map.of(
                    "accessToken", accessToken,
                    "type", "Bearer",
                    "user", Map.of(
                            "username", user.getUsername(),
                            "email", user.getEmail(),
                            "role", user.getRole().name()
                    )
            );

            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "잘못된 사용자명 또는 비밀번호입니다."));
        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "인증에 실패했습니다."));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "로그인 처리 중 오류가 발생했습니다."));
        }
    }

    /**
     * 사용자 회원가입 API
     *
     * @param registerRequest 회원가입 요청 정보
     * @return 생성된 사용자 정보
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        try {
            User user = userService.createUser(
                    registerRequest.getUsername(),
                    registerRequest.getPassword(),
                    registerRequest.getEmail(),
                    registerRequest.getRole()
            );

            return ResponseEntity.ok(Map.of(
                    "message", "회원가입이 완료되었습니다.",
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "role", user.getRole().name()
            ));

        } catch (RuntimeException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "회원가입 처리 중 오류가 발생했습니다."));
        }
    }
}