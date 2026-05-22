package com.sentinel.target.service;

import com.sentinel.target.entity.Target;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TargetRepository extends JpaRepository<Target, Long> {

    List<Target> findByOwnerIdAndActiveTrue(Long ownerId);

    Optional<Target> findByIdAndOwnerId(Long id, Long ownerId);
}
