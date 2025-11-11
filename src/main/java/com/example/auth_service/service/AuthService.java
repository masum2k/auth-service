package com.example.auth_service.service;

import com.example.auth_service.dto.AuthResponse;
import com.example.auth_service.dto.LoginRequest;
import com.example.auth_service.dto.RefreshTokenRequest;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.exception.EmailAlreadyExistsException;
import com.example.auth_service.exception.InvalidCredentialsException;
import com.example.auth_service.exception.TokenRefreshException;
import com.example.auth_service.exception.UserNotFoundException;
import com.example.auth_service.model.AppUser;
import com.example.auth_service.model.RefreshToken;
import com.example.auth_service.model.Role;
import com.example.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            log.warn("Registration attempt with existing email: {}", request.email());
            throw new EmailAlreadyExistsException("Email already in use: " + request.email());
        }

        AppUser user = new AppUser();
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));
        user.setAuthorities(Set.of(Role.ROLE_USER));
        userRepository.save(user);

        String accessToken = jwtService.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

        log.info("User registered successfully: {}", request.email());
        return new AuthResponse(accessToken, refreshToken.getToken());
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.email(), request.password())
            );
        } catch (BadCredentialsException e) {
            log.warn("Failed login attempt for email: {}", request.email());
            throw new InvalidCredentialsException("Invalid email or password");
        }

        AppUser user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + request.email()));

        String accessToken = jwtService.generateToken(user);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getEmail());

        log.info("User logged in successfully: {}", request.email());
        return new AuthResponse(accessToken, refreshToken.getToken());
    }

    public AuthResponse refreshToken(RefreshTokenRequest request) {
        return refreshTokenService.findByToken(request.refreshToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String newAccessToken = jwtService.generateToken(user);
                    return new AuthResponse(newAccessToken, request.refreshToken());
                })
                .orElseThrow(() -> new TokenRefreshException("Refresh token is not in database or expired!"));
    }
}