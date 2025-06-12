package com.sb02.practice.security.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenRefreshRequest {

    @NotBlank(message = "Refresh token은 필수입니다")
    private String refreshToken;
}