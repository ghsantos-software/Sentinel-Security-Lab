package com.sentinel.reports.controller;

import com.sentinel.reports.dto.ReportResponse;
import com.sentinel.reports.service.ReportService;
import com.sentinel.shared.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/reports")
@Tag(name = "Reports")
public class ReportController {

    private final ReportService reportService;

    public ReportController(ReportService reportService) {
        this.reportService = reportService;
    }

    @PostMapping("/generate/{jobId}")
    @Operation(summary = "Generate a report from a completed scan job")
    public ResponseEntity<ApiResponse<ReportResponse>> generate(
            @PathVariable Long jobId,
            @AuthenticationPrincipal UserDetails user
    ) {
        return ResponseEntity.ok(ApiResponse.ok(reportService.generateReport(jobId, user.getUsername())));
    }

    @GetMapping
    @Operation(summary = "List all your reports")
    public ResponseEntity<ApiResponse<List<ReportResponse>>> list(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(ApiResponse.ok(reportService.listReports(user.getUsername())));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get a full report with all findings")
    public ResponseEntity<ApiResponse<ReportResponse>> get(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(reportService.getReport(id)));
    }
}
