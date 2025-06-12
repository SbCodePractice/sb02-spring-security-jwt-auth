package com.sb02.practice.security.service;

import com.sb02.practice.security.config.JwtProperties;
import com.sb02.practice.security.entity.RefreshToken;
import com.sb02.practice.security.entity.User;
import com.sb02.practice.security.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Optional;

@Service
@Transactional
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;
    private final SecureRandom secureRandom = new SecureRandom();

    // 동시 활성 토큰 제한 (보안상 한 사용자당 최대 5개)
    private static final int MAX_ACTIVE_TOKENS_PER_USER = 5;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository,
                               JwtProperties jwtProperties) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtProperties = jwtProperties;
    }

    /**
     * 사용자를 위한 새로운 Refresh Token을 생성한다.
     * 토큰 회전(Token Rotation) 패턴 적용
     *
     * @param user 토큰을 생성할 사용자
     * @return 생성된 RefreshToken 엔티티
     */
    public RefreshToken createRefreshToken(User user) {
        // 사용자의 활성 토큰 수 확인
        long activeTokenCount = refreshTokenRepository.countActiveTokensByUser(user);

        // 최대 허용 개수 초과 시 가장 오래된 토큰들 무효화
        if (activeTokenCount >= MAX_ACTIVE_TOKENS_PER_USER) {
            cleanupOldTokens(user);
        }

        // 새로운 토큰 생성
        String token = generateSecureRandomToken();
        LocalDateTime expiresAt = LocalDateTime.now()
                .plusSeconds(jwtProperties.refreshTokenExpiration() / 1000);

        RefreshToken refreshToken = new RefreshToken(token, user, expiresAt);
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Refresh Token을 검증하고 조회한다.
     *
     * @param token 검증할 Refresh Token 문자열
     * @return 유효한 RefreshToken 엔티티 또는 빈 Optional
     */
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .filter(RefreshToken::isValid);
    }

    /**
     * Refresh Token을 사용 처리한다.
     * 토큰 회전 패턴에서 사용된 토큰 추적을 위함
     *
     * @param refreshToken 사용할 RefreshToken
     */
    public void markAsUsed(RefreshToken refreshToken) {
        refreshToken.setUsedAt(LocalDateTime.now());
        refreshTokenRepository.save(refreshToken);
    }

    /**
     * 사용자의 모든 Refresh Token을 무효화한다.
     * 로그아웃, 비밀번호 변경, 보안 위반 시 사용
     *
     * @param user 토큰을 무효화할 사용자
     */
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
    }

    /**
     * 특정 Refresh Token을 무효화한다.
     *
     * @param refreshToken 무효화할 RefreshToken
     */
    public void revokeToken(RefreshToken refreshToken) {
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);
    }

    /**
     * 만료된 토큰들을 데이터베이스에서 삭제한다.
     * 정기적으로 실행하여 저장소 크기 관리
     */
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
    }

    /**
     * 사용자의 오래된 토큰들을 정리한다.
     *
     * @param user 정리할 사용자
     */
    private void cleanupOldTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
    }

    /**
     * 암호학적으로 안전한 랜덤 토큰을 생성한다.
     *
     * @return Base64 인코딩된 랜덤 토큰 문자열
     */
    private String generateSecureRandomToken() {
        byte[] tokenBytes = new byte[32]; // 256비트
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
