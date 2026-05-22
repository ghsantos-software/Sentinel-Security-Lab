package com.sentinel.target.service;

import com.sentinel.auth.entity.User;
import com.sentinel.auth.service.UserRepository;
import com.sentinel.shared.exception.ResourceNotFoundException;
import com.sentinel.target.dto.TargetRequest;
import com.sentinel.target.dto.TargetResponse;
import com.sentinel.target.entity.Target;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class TargetService {

    private final TargetRepository targetRepository;
    private final UserRepository userRepository;

    public TargetService(TargetRepository targetRepository, UserRepository userRepository) {
        this.targetRepository = targetRepository;
        this.userRepository = userRepository;
    }

    public List<TargetResponse> listTargets(String username) {
        var user = findUser(username);
        return targetRepository.findByOwnerIdAndActiveTrue(user.getId())
                .stream()
                .map(TargetResponse::from)
                .toList();
    }

    public TargetResponse getTarget(Long id, String username) {
        var user = findUser(username);
        var target = targetRepository.findByIdAndOwnerId(id, user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Target", id));
        return TargetResponse.from(target);
    }

    @Transactional
    public TargetResponse createTarget(TargetRequest request, String username) {
        var user = findUser(username);

        var target = Target.builder()
                .name(request.name())
                .baseUrl(request.baseUrl())
                .description(request.description())
                .environment(request.environment())
                .owner(user)
                .build();

        return TargetResponse.from(targetRepository.save(target));
    }

    @Transactional
    public TargetResponse updateTarget(Long id, TargetRequest request, String username) {
        var user = findUser(username);
        var target = targetRepository.findByIdAndOwnerId(id, user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Target", id));

        target.setName(request.name());
        target.setBaseUrl(request.baseUrl());
        target.setDescription(request.description());
        target.setEnvironment(request.environment());
        target.setUpdatedAt(Instant.now());

        return TargetResponse.from(targetRepository.save(target));
    }

    @Transactional
    public void deleteTarget(Long id, String username) {
        var user = findUser(username);
        var target = targetRepository.findByIdAndOwnerId(id, user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Target", id));

        target.setActive(false);
        target.setUpdatedAt(Instant.now());
        targetRepository.save(target);
    }

    private User findUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
