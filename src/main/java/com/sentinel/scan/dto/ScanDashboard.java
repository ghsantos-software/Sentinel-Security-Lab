package com.sentinel.scan.dto;

import java.util.List;
import java.util.Map;

public record ScanDashboard(
        Long jobId,
        String targetName,
        String targetUrl,
        String status,
        int totalFindings,
        Map<String, Long> bySeverity,
        Map<String, Long> byCategory,
        List<FindingResponse> topFindings,
        int riskScore,
        String riskLevel
) {}
