package com.sentinel.scan.dto;

import com.sentinel.scan.entity.ScanFinding;

import java.util.Map;

public record FindingResponse(
        Long id,
        String category,
        String severity,
        String title,
        String description,
        Map<String, Object> details
) {
    public static FindingResponse from(ScanFinding finding) {
        return new FindingResponse(
                finding.getId(),
                finding.getCategory(),
                finding.getSeverity().name(),
                finding.getTitle(),
                finding.getDescription(),
                finding.getDetails()
        );
    }
}
