package com.example.auth_service.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken
) {
}