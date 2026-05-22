package com.sentinel.scan.service;

import com.sentinel.scan.entity.ScanFinding;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ScanFindingRepository extends JpaRepository<ScanFinding, Long> {

    List<ScanFinding> findByJobId(Long jobId);

    List<ScanFinding> findByJobIdOrderBySeverityDesc(Long jobId);
}
