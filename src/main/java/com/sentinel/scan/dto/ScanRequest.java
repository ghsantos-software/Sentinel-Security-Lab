package com.sentinel.scan.dto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record ScanRequest(
        @NotNull(message = "Target ID is required")
        Long targetId,

        @NotEmpty(message = "At least one scan type must be selected")
        List<ScanType> scanTypes
) {
    public enum ScanType {
        SECURITY_HEADERS,
        CORS,
        SWAGGER_DETECTION,
        JWT_ANALYSIS,
        RATE_LIMIT,
        RESPONSE_ANALYSIS,
        UNAUTH_ENDPOINTS
    }
}
