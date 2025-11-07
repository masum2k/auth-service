package com.example.auth_service.dto;

// Artık Access Token ve Refresh Token döneceğiz
public record AuthResponse(
        String accessToken,
        String refreshToken
) {
}