package com.sentinel.scan.dto;

import com.sentinel.scan.entity.ScanJob;

import java.time.Instant;
import java.util.List;

public record ScanJobResponse(
        Long id,
        Long targetId,
        String targetName,
        String status,
        List<String> scanTypes,
        Instant startedAt,
        Instant finishedAt,
        Instant createdAt,
        int findingsCount
) {
    public static ScanJobResponse from(ScanJob job) {
        int count = job.getFindings() == null ? 0 : job.getFindings().size();
        return new ScanJobResponse(
                job.getId(),
                job.getTarget().getId(),
                job.getTarget().getName(),
                job.getStatus().name(),
                job.getScanTypes(),
                job.getStartedAt(),
                job.getFinishedAt(),
                job.getCreatedAt(),
                count
        );
    }
}
