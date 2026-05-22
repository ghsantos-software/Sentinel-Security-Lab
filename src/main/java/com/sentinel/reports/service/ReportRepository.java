package com.sentinel.reports.service;

import com.sentinel.reports.entity.Report;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface ReportRepository extends JpaRepository<Report, Long> {

    @Query("SELECT r FROM Report r WHERE r.generatedBy.id = :userId ORDER BY r.createdAt DESC")
    List<Report> findByUserId(Long userId);

    Optional<Report> findByJobId(Long jobId);
}
