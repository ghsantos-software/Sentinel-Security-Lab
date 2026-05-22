package com.sentinel.scan.controller;

import com.sentinel.scan.dto.FindingResponse;
import com.sentinel.scan.dto.ScanDashboard;
import com.sentinel.scan.dto.ScanJobResponse;
import com.sentinel.scan.dto.ScanRequest;
import com.sentinel.scan.service.DashboardService;
import com.sentinel.scan.service.JwtAnalyzerService;
import com.sentinel.scan.service.ScanService;
import com.sentinel.shared.dto.ApiResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scans")
@Tag(name = "Scans")
public class ScanController {

    private final ScanService scanService;
    private final DashboardService dashboardService;
    private final JwtAnalyzerService jwtAnalyzerService;

    public ScanController(ScanService scanService,
                          DashboardService dashboardService,
                          JwtAnalyzerService jwtAnalyzerService) {
        this.scanService = scanService;
        this.dashboardService = dashboardService;
        this.jwtAnalyzerService = jwtAnalyzerService;
    }

    @PostMapping
    @Operation(
            summary = "Start a scan job",
            description = "Runs the selected checks against a registered target. The job is executed asynchronously — poll GET /api/scans/{id} for status."
    )
    public ResponseEntity<ApiResponse<ScanJobResponse>> startScan(
            @Valid @RequestBody ScanRequest request,
            @AuthenticationPrincipal UserDetails user
    ) {
        var job = scanService.createScanJob(request, user.getUsername());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(ApiResponse.ok("Scan started", job));
    }

    @PostMapping("/full/{targetId}")
    @Operation(
            summary = "Run all available scan types against a target",
            description = "Convenience endpoint — equivalent to submitting a scan with all scan types selected."
    )
    public ResponseEntity<ApiResponse<ScanJobResponse>> fullScan(
            @PathVariable Long targetId,
            @AuthenticationPrincipal UserDetails user
    ) {
        var allTypes = Arrays.asList(ScanRequest.ScanType.values());
        var request = new ScanRequest(targetId, allTypes);
        var job = scanService.createScanJob(request, user.getUsername());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(ApiResponse.ok("Full scan started", job));
    }

    @GetMapping
    @Operation(summary = "List all your scan jobs")
    public ResponseEntity<ApiResponse<List<ScanJobResponse>>> listJobs(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(ApiResponse.ok(scanService.listJobs(user.getUsername())));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get scan job status")
    public ResponseEntity<ApiResponse<ScanJobResponse>> getJob(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(scanService.getJob(id)));
    }

    @GetMapping("/{id}/findings")
    @Operation(summary = "Get all findings from a scan, sorted by severity")
    public ResponseEntity<ApiResponse<List<FindingResponse>>> getFindings(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(scanService.getFindings(id)));
    }

    @GetMapping("/{id}/dashboard")
    @Operation(
            summary = "Get aggregated dashboard for a scan",
            description = "Returns findings grouped by severity and category, top issues, and overall risk score."
    )
    public ResponseEntity<ApiResponse<ScanDashboard>> getDashboard(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(dashboardService.buildDashboard(id)));
    }

    @PostMapping("/analyze-token")
    @Operation(
            summary = "Decode and analyze a JWT token",
            description = "Decodes the token header and payload without verifying the signature. Flags common issues like missing exp, alg=none, or expired tokens."
    )
    public ResponseEntity<ApiResponse<Map<String, Object>>> analyzeToken(
            @RequestBody Map<String, String> body
    ) {
        String token = body.get("token");
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().body(ApiResponse.error("'token' field is required"));
        }
        return ResponseEntity.ok(ApiResponse.ok(jwtAnalyzerService.analyzeToken(token)));
    }

    @GetMapping("/types")
    @Operation(summary = "List all available scan types")
    public ResponseEntity<ApiResponse<List<String>>> listScanTypes() {
        var types = Arrays.stream(ScanRequest.ScanType.values())
                .map(Enum::name)
                .toList();
        return ResponseEntity.ok(ApiResponse.ok(types));
    }
}
