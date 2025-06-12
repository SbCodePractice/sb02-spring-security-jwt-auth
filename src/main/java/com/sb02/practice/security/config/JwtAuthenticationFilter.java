package com.sb02.practice.security.config;

import com.sb02.practice.security.exception.*;
import com.sb02.practice.security.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            // Authorization 헤더에서 JWT 토큰 추출
            String jwt = extractJwtFromRequest(request);

            if (jwt != null) {
                // JWT 토큰 검증 및 사용자 정보 추출
                validateAndProcessToken(jwt, request);
            }

        } catch (JwtAuthenticationException ex) {
            // JWT 관련 예외는 request attribute에 저장하여 EntryPoint에서 처리
            request.setAttribute("jwt.exception", ex);
        } catch (Exception ex) {
            // 기타 예외는 일반적인 인증 예외로 처리
            logger.error("JWT 인증 처리 중 예상치 못한 오류 발생", ex);
            request.setAttribute("jwt.exception",
                    new JwtAuthenticationException("JWT 처리 중 내부 오류가 발생했습니다.", 500, "JWT_INTERNAL_ERROR"));
        }

        // 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }

    /**
     * Authorization 헤더에서 JWT 토큰을 추출한다.
     *
     * @param request HTTP 요청
     * @return JWT 토큰 문자열 또는 null
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        if (bearerToken == null) {
            return null; // 토큰이 없는 것은 정상 (public 엔드포인트일 수 있음)
        }

        if (!bearerToken.startsWith("Bearer ")) {
            throw new JwtTokenMalformedException("Authorization 헤더는 'Bearer '로 시작해야 합니다.");
        }

        String token = bearerToken.substring(7);
        if (token.trim().isEmpty()) {
            throw new JwtTokenMissingException("Bearer 토큰이 비어있습니다.");
        }

        return token;
    }

    /**
     * JWT 토큰을 검증하고 SecurityContext에 인증 정보를 설정한다.
     *
     * @param jwt JWT 토큰
     * @param request HTTP 요청
     */
    private void validateAndProcessToken(String jwt, HttpServletRequest request) {
        try {
            // 토큰 유효성 검증
            if (!jwtUtil.validateToken(jwt)) {
                throw new JwtAuthenticationException("유효하지 않은 JWT 토큰입니다.", 401, "JWT_TOKEN_INVALID");
            }

            // 토큰에서 사용자 정보 추출
            String username = jwtUtil.extractUsername(jwt);
            String role = jwtUtil.extractRole(jwt);

            // 현재 SecurityContext에 인증 정보가 없는 경우에만 처리
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // JWT 토큰에서 권한 정보 추출
                List<GrantedAuthority> authorities = Collections.singletonList(
                        new SimpleGrantedAuthority("ROLE_" + role)
                );

                // 인증 객체 생성
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);

                // 요청 상세 정보 설정 (IP 주소, 세션 ID 등)
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                // SecurityContext에 인증 정보 설정
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (ExpiredJwtException e) {
            throw new JwtTokenExpiredException("JWT 토큰이 만료되었습니다.");
        } catch (UnsupportedJwtException e) {
            throw new JwtUnsupportedException("지원하지 않는 JWT 토큰입니다.");
        } catch (MalformedJwtException e) {
            throw new JwtTokenMalformedException("JWT 토큰 형식이 올바르지 않습니다.");
        } catch (SignatureException e) {
            throw new JwtSignatureException("JWT 토큰의 서명이 유효하지 않습니다.");
        } catch (IllegalArgumentException e) {
            throw new JwtTokenMalformedException("JWT 토큰이 비어있거나 올바르지 않습니다.");
        }
    }
}
