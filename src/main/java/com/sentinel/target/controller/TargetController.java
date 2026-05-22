package com.sentinel.target.controller;

import com.sentinel.shared.dto.ApiResponse;
import com.sentinel.target.dto.TargetRequest;
import com.sentinel.target.dto.TargetResponse;
import com.sentinel.target.service.TargetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/targets")
@Tag(name = "Targets")
public class TargetController {

    private final TargetService targetService;

    public TargetController(TargetService targetService) {
        this.targetService = targetService;
    }

    @GetMapping
    @Operation(summary = "List all your registered targets")
    public ResponseEntity<ApiResponse<List<TargetResponse>>> list(@AuthenticationPrincipal UserDetails user) {
        return ResponseEntity.ok(ApiResponse.ok(targetService.listTargets(user.getUsername())));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get a target by ID")
    public ResponseEntity<ApiResponse<TargetResponse>> get(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails user
    ) {
        return ResponseEntity.ok(ApiResponse.ok(targetService.getTarget(id, user.getUsername())));
    }

    @PostMapping
    @Operation(summary = "Register a new target API")
    public ResponseEntity<ApiResponse<TargetResponse>> create(
            @Valid @RequestBody TargetRequest request,
            @AuthenticationPrincipal UserDetails user
    ) {
        var target = targetService.createTarget(request, user.getUsername());
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.ok("Target registered", target));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update a target")
    public ResponseEntity<ApiResponse<TargetResponse>> update(
            @PathVariable Long id,
            @Valid @RequestBody TargetRequest request,
            @AuthenticationPrincipal UserDetails user
    ) {
        return ResponseEntity.ok(ApiResponse.ok(targetService.updateTarget(id, request, user.getUsername())));
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Remove a target")
    public ResponseEntity<ApiResponse<Void>> delete(
            @PathVariable Long id,
            @AuthenticationPrincipal UserDetails user
    ) {
        targetService.deleteTarget(id, user.getUsername());
        return ResponseEntity.ok(ApiResponse.ok("Target removed", null));
    }
}
