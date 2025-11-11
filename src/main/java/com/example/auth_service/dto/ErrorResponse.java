package com.example.auth_service.dto;

public record ErrorResponse(int statusCode, String message, long timestamp) {
}