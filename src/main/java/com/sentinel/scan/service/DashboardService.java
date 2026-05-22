package com.sentinel.scan.service;

import com.sentinel.scan.dto.FindingResponse;
import com.sentinel.scan.dto.ScanDashboard;
import com.sentinel.scan.entity.ScanFinding;
import com.sentinel.shared.exception.ResourceNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class DashboardService {

    private static final Map<ScanFinding.Severity, Integer> RISK_WEIGHTS = Map.of(
            ScanFinding.Severity.CRITICAL, 25,
            ScanFinding.Severity.HIGH, 15,
            ScanFinding.Severity.MEDIUM, 8,
            ScanFinding.Severity.LOW, 3,
            ScanFinding.Severity.INFO, 0
    );

    private final ScanJobRepository jobRepository;
    private final ScanFindingRepository findingRepository;

    public DashboardService(ScanJobRepository jobRepository, ScanFindingRepository findingRepository) {
        this.jobRepository = jobRepository;
        this.findingRepository = findingRepository;
    }

    public ScanDashboard buildDashboard(Long jobId) {
        var job = jobRepository.findById(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("ScanJob", jobId));

        var findings = findingRepository.findByJobIdOrderBySeverityDesc(jobId);

        Map<String, Long> bySeverity = findings.stream()
                .collect(Collectors.groupingBy(f -> f.getSeverity().name(), Collectors.counting()));

        Map<String, Long> byCategory = findings.stream()
                .collect(Collectors.groupingBy(ScanFinding::getCategory, Collectors.counting()));

        int riskScore = Math.min(findings.stream()
                .mapToInt(f -> RISK_WEIGHTS.getOrDefault(f.getSeverity(), 0))
                .sum(), 100);

        // top 5 non-INFO findings for the summary panel
        List<FindingResponse> topFindings = findings.stream()
                .filter(f -> f.getSeverity() != ScanFinding.Severity.INFO)
                .limit(5)
                .map(FindingResponse::from)
                .toList();

        return new ScanDashboard(
                jobId,
                job.getTarget().getName(),
                job.getTarget().getBaseUrl(),
                job.getStatus().name(),
                findings.size(),
                bySeverity,
                byCategory,
                topFindings,
                riskScore,
                riskLevel(riskScore)
        );
    }

    private String riskLevel(int score) {
        if (score >= 75) return "CRITICAL";
        if (score >= 50) return "HIGH";
        if (score >= 25) return "MEDIUM";
        if (score >= 10) return "LOW";
        return "INFO";
    }
}
