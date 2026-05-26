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
    @Operation(summary = "Inicia um scan job")
    public ResponseEntity<ApiResponse<ScanJobResponse>> startScan(
            @Valid @RequestBody ScanRequest request,
            @AuthenticationPrincipal UserDetails user
    ) {
        var job = scanService.createScanJob(request, user.getUsername());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(ApiResponse.ok("Scan started", job));
    }

    @PostMapping("/full/{targetId}")
    @Operation(summary = "Roda todos os tipos de scan no target")
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
    @Operation(summary = "Lista seus scan jobs")
    public ResponseEntity<ApiResponse<List<ScanJobResponse>>> listJobs(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(ApiResponse.ok(scanService.listJobs(user.getUsername())));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Status de um scan job")
    public ResponseEntity<ApiResponse<ScanJobResponse>> getJob(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(scanService.getJob(id)));
    }

    @GetMapping("/{id}/findings")
    @Operation(summary = "Findings do scan ordenados por severidade")
    public ResponseEntity<ApiResponse<List<FindingResponse>>> getFindings(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(scanService.getFindings(id)));
    }

    @GetMapping("/{id}/dashboard")
    @Operation(summary = "Dashboard com resumo do scan e risk score")
    public ResponseEntity<ApiResponse<ScanDashboard>> getDashboard(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(dashboardService.buildDashboard(id)));
    }

    @PostMapping("/analyze-token")
    @Operation(summary = "Decodifica e analisa um JWT sem precisar da secret")
    public ResponseEntity<ApiResponse<Map<String, Object>>> analyzeToken(
            @RequestBody Map<String, String> body
    ) {
        String token = body.get("token");
        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().body(ApiResponse.error("campo 'token' obrigatorio"));
        }
        return ResponseEntity.ok(ApiResponse.ok(jwtAnalyzerService.analyzeToken(token)));
    }

    @GetMapping("/types")
    @Operation(summary = "Lista os tipos de scan disponíveis")
    public ResponseEntity<ApiResponse<List<String>>> listScanTypes() {
        var types = Arrays.stream(ScanRequest.ScanType.values())
                .map(Enum::name)
                .toList();
        return ResponseEntity.ok(ApiResponse.ok(types));
    }
}
