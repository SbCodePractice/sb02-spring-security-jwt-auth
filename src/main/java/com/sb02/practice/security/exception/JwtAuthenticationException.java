package com.sb02.practice.security.exception;


import org.springframework.security.core.AuthenticationException;

/**
 * JWT 인증 관련 예외의 부모 클래스
 */
public class JwtAuthenticationException extends AuthenticationException {

    private final int httpStatus;
    private final String errorCode;

    public JwtAuthenticationException(String message, int httpStatus, String errorCode) {
        super(message);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    public JwtAuthenticationException(String message, Throwable cause, int httpStatus, String errorCode) {
        super(message, cause);
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    public String getErrorCode() {
        return errorCode;
    }
}