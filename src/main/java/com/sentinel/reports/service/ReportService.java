package com.sentinel.reports.service;

import com.sentinel.auth.service.UserRepository;
import com.sentinel.reports.dto.ReportResponse;
import com.sentinel.reports.entity.Report;
import com.sentinel.scan.dto.FindingResponse;
import com.sentinel.scan.entity.ScanFinding;
import com.sentinel.scan.entity.ScanJob;
import com.sentinel.scan.service.ScanFindingRepository;
import com.sentinel.scan.service.ScanJobRepository;
import com.sentinel.shared.exception.ResourceNotFoundException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class ReportService {

    private static final Map<ScanFinding.Severity, Integer> RISK_WEIGHTS = Map.of(
            ScanFinding.Severity.CRITICAL, 25,
            ScanFinding.Severity.HIGH, 15,
            ScanFinding.Severity.MEDIUM, 8,
            ScanFinding.Severity.LOW, 3,
            ScanFinding.Severity.INFO, 0
    );

    private final ReportRepository reportRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanFindingRepository findingRepository;
    private final UserRepository userRepository;

    public ReportService(ReportRepository reportRepository,
                         ScanJobRepository scanJobRepository,
                         ScanFindingRepository findingRepository,
                         UserRepository userRepository) {
        this.reportRepository = reportRepository;
        this.scanJobRepository = scanJobRepository;
        this.findingRepository = findingRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public ReportResponse generateReport(Long jobId, String username) {
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        var job = scanJobRepository.findById(jobId)
                .orElseThrow(() -> new ResourceNotFoundException("ScanJob", jobId));

        if (job.getStatus() != ScanJob.Status.COMPLETED) {
            throw new IllegalArgumentException("Scan job has not completed yet (status: " + job.getStatus() + ")");
        }

        var findings = findingRepository.findByJobIdOrderBySeverityDesc(jobId);

        return reportRepository.findByJobId(jobId)
                .map(existing -> toResponse(existing, findings))
                .orElseGet(() -> {
                    var report = Report.builder()
                            .job(job)
                            .target(job.getTarget())
                            .generatedBy(user)
                            .findingsCount(findings.size())
                            .riskScore(calculateRiskScore(findings))
                            .summary(buildSummary(job, findings))
                            .build();
                    return toResponse(reportRepository.save(report), findings);
                });
    }

    public List<ReportResponse> listReports(String username) {
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return reportRepository.findByUserId(user.getId()).stream()
                .map(r -> {
                    var findings = findingRepository.findByJobIdOrderBySeverityDesc(r.getJob().getId());
                    return toResponse(r, findings);
                })
                .toList();
    }

    public ReportResponse getReport(Long id) {
        var report = reportRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Report", id));
        var findings = findingRepository.findByJobIdOrderBySeverityDesc(report.getJob().getId());
        return toResponse(report, findings);
    }

    private ReportResponse toResponse(Report report, List<ScanFinding> findings) {
        var findingDtos = findings.stream().map(FindingResponse::from).toList();
        var byCategory = findings.stream()
                .collect(Collectors.groupingBy(ScanFinding::getCategory, Collectors.counting()));
        return ReportResponse.from(report, findingDtos, byCategory);
    }

    private int calculateRiskScore(List<ScanFinding> findings) {
        return Math.min(findings.stream()
                .mapToInt(f -> RISK_WEIGHTS.getOrDefault(f.getSeverity(), 0))
                .sum(), 100);
    }

    private String buildSummary(ScanJob job, List<ScanFinding> findings) {
        long critical = count(findings, ScanFinding.Severity.CRITICAL);
        long high     = count(findings, ScanFinding.Severity.HIGH);
        long medium   = count(findings, ScanFinding.Severity.MEDIUM);
        long low      = count(findings, ScanFinding.Severity.LOW);

        var categories = findings.stream()
                .map(ScanFinding::getCategory)
                .distinct()
                .sorted()
                .collect(Collectors.joining(", "));

        return String.format(
                "Scan of '%s' completed — %d findings across [%s]. " +
                "Breakdown: %d critical, %d high, %d medium, %d low. " +
                "Review critical and high severity items first.",
                job.getTarget().getName(), findings.size(), categories,
                critical, high, medium, low
        );
    }

    private long count(List<ScanFinding> findings, ScanFinding.Severity severity) {
        return findings.stream().filter(f -> f.getSeverity() == severity).count();
    }
}
