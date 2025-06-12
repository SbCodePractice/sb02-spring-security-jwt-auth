package com.sb02.practice.security.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 500)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    @Column(nullable = false)
    private boolean revoked = false;

    // 생성자
    public RefreshToken(String token, User user, LocalDateTime expiresAt) {
        this.token = token;
        this.user = user;
        this.expiresAt = expiresAt;
        this.createdAt = LocalDateTime.now();
    }

    /**
     * Refresh Token이 만료되었는지 확인한다.
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * Refresh Token이 유효한지 확인한다.
     * 만료되지 않았고 무효화되지 않은 경우에만 유효
     */
    public boolean isValid() {
        return !revoked && !isExpired();
    }
}