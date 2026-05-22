package com.sentinel.reports.dto;

import com.sentinel.reports.entity.Report;
import com.sentinel.scan.dto.FindingResponse;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record ReportResponse(
        Long id,
        Long jobId,
        String targetName,
        String targetUrl,
        String summary,
        Integer riskScore,
        String riskLevel,
        FindingBreakdown findings,
        Instant createdAt
) {
    public record FindingBreakdown(
            int total,
            int critical,
            int high,
            int medium,
            int low,
            int info,
            Map<String, Long> byCategory,
            List<FindingResponse> all
    ) {}

    public static ReportResponse from(Report report, List<FindingResponse> findings,
                                      Map<String, Long> byCategory) {
        int critical = (int) findings.stream().filter(f -> "CRITICAL".equals(f.severity())).count();
        int high     = (int) findings.stream().filter(f -> "HIGH".equals(f.severity())).count();
        int medium   = (int) findings.stream().filter(f -> "MEDIUM".equals(f.severity())).count();
        int low      = (int) findings.stream().filter(f -> "LOW".equals(f.severity())).count();
        int info     = (int) findings.stream().filter(f -> "INFO".equals(f.severity())).count();

        return new ReportResponse(
                report.getId(),
                report.getJob().getId(),
                report.getTarget().getName(),
                report.getTarget().getBaseUrl(),
                report.getSummary(),
                report.getRiskScore(),
                riskLevel(report.getRiskScore()),
                new FindingBreakdown(findings.size(), critical, high, medium, low, info, byCategory, findings),
                report.getCreatedAt()
        );
    }

    private static String riskLevel(Integer score) {
        if (score == null) return "UNKNOWN";
        if (score >= 75) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 25) return "MEDIUM";
        if (score >= 10) return "LOW";
        return "INFO";
    }
}
