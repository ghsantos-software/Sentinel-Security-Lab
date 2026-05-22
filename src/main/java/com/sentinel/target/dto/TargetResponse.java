package com.sentinel.target.dto;

import com.sentinel.target.entity.Target;

import java.time.Instant;

public record TargetResponse(
        Long id,
        String name,
        String baseUrl,
        String description,
        String environment,
        boolean active,
        Instant createdAt
) {
    public static TargetResponse from(Target target) {
        return new TargetResponse(
                target.getId(),
                target.getName(),
                target.getBaseUrl(),
                target.getDescription(),
                target.getEnvironment().name(),
                target.isActive(),
                target.getCreatedAt()
        );
    }
}
