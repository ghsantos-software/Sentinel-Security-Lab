package com.sentinel.auth.dto;

import com.sentinel.auth.entity.User;

import java.time.Instant;

public record UserResponse(
        Long id,
        String username,
        String email,
        String role,
        Instant createdAt
) {
    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name(),
                user.getCreatedAt()
        );
    }
}
