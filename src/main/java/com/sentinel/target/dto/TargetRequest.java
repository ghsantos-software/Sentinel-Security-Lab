package com.sentinel.target.dto;

import com.sentinel.target.entity.Target;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record TargetRequest(
        @NotBlank(message = "Name is required")
        @Size(max = 100)
        String name,

        @NotBlank(message = "Base URL is required")
        @Pattern(
                regexp = "^https?://(localhost|127\\.0\\.0\\.1|\\[::1\\]|10\\.\\d+\\.\\d+\\.\\d+|172\\.(1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+)(:\\d+)?(/.*)?$",
                message = "Only local/private network URLs are allowed (localhost, 127.x, 10.x, 172.16-31.x, 192.168.x)"
        )
        String baseUrl,

        String description,

        @NotNull(message = "Environment is required")
        Target.Environment environment
) {}
