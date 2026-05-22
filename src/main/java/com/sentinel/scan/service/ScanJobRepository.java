package com.sentinel.scan.service;

import com.sentinel.scan.entity.ScanJob;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ScanJobRepository extends JpaRepository<ScanJob, Long> {

    @Query("SELECT j FROM ScanJob j WHERE j.requestedBy.id = :userId ORDER BY j.createdAt DESC")
    List<ScanJob> findByUserId(Long userId);

    @Query("SELECT j FROM ScanJob j WHERE j.target.id = :targetId ORDER BY j.createdAt DESC")
    List<ScanJob> findByTargetId(Long targetId);
}
