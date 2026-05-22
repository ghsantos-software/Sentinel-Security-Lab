package com.sentinel.scan.service;

import com.sentinel.auth.service.UserRepository;
import com.sentinel.scan.dto.FindingResponse;
import com.sentinel.scan.dto.ScanJobResponse;
import com.sentinel.scan.dto.ScanRequest;
import com.sentinel.scan.entity.ScanFinding;
import com.sentinel.scan.entity.ScanJob;
import com.sentinel.shared.exception.ResourceNotFoundException;
import com.sentinel.target.service.TargetRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final ScanJobRepository jobRepository;
    private final ScanFindingRepository findingRepository;
    private final UserRepository userRepository;
    private final TargetRepository targetRepository;
    private final HeaderScannerService headerScanner;
    private final CorsScannerService corsScanner;
    private final SwaggerDetectorService swaggerDetector;
    private final JwtAnalyzerService jwtAnalyzer;
    private final RateLimitTesterService rateLimitTester;
    private final ResponseAnalyzerService responseAnalyzer;
    private final UnauthEndpointScannerService unauthScanner;

    public ScanService(ScanJobRepository jobRepository,
                       ScanFindingRepository findingRepository,
                       UserRepository userRepository,
                       TargetRepository targetRepository,
                       HeaderScannerService headerScanner,
                       CorsScannerService corsScanner,
                       SwaggerDetectorService swaggerDetector,
                       JwtAnalyzerService jwtAnalyzer,
                       RateLimitTesterService rateLimitTester,
                       ResponseAnalyzerService responseAnalyzer,
                       UnauthEndpointScannerService unauthScanner) {
        this.jobRepository = jobRepository;
        this.findingRepository = findingRepository;
        this.userRepository = userRepository;
        this.targetRepository = targetRepository;
        this.headerScanner = headerScanner;
        this.corsScanner = corsScanner;
        this.swaggerDetector = swaggerDetector;
        this.jwtAnalyzer = jwtAnalyzer;
        this.rateLimitTester = rateLimitTester;
        this.responseAnalyzer = responseAnalyzer;
        this.unauthScanner = unauthScanner;
    }

    @Transactional
    public ScanJobResponse createScanJob(ScanRequest request, String username) {
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        var target = targetRepository.findByIdAndOwnerId(request.targetId(), user.getId())
                .orElseThrow(() -> new ResourceNotFoundException("Target", request.targetId()));

        var job = ScanJob.builder()
                .target(target)
                .requestedBy(user)
                .scanTypes(request.scanTypes().stream().map(Enum::name).toList())
                .status(ScanJob.Status.PENDING)
                .build();

        var saved = jobRepository.save(job);
        executeScan(saved.getId());
        return ScanJobResponse.from(saved);
    }

    @Async("taskExecutor")
    public void executeScan(Long jobId) {
        var job = jobRepository.findById(jobId).orElse(null);
        if (job == null) return;

        log.info("Starting scan job {} for target '{}'", jobId, job.getTarget().getName());

        job.setStatus(ScanJob.Status.RUNNING);
        job.setStartedAt(Instant.now());
        jobRepository.save(job);

        List<ScanFinding> allFindings = new ArrayList<>();
        String baseUrl = job.getTarget().getBaseUrl();

        try {
            for (String type : job.getScanTypes()) {
                List<ScanFinding> findings = switch (type) {
                    case "SECURITY_HEADERS" -> headerScanner.scan(baseUrl);
                    case "CORS"             -> corsScanner.scan(baseUrl);
                    case "SWAGGER_DETECTION" -> swaggerDetector.scan(baseUrl);
                    case "JWT_ANALYSIS"     -> jwtAnalyzer.scan(baseUrl);
                    case "RATE_LIMIT"       -> rateLimitTester.scan(baseUrl);
                    case "RESPONSE_ANALYSIS" -> responseAnalyzer.scan(baseUrl);
                    case "UNAUTH_ENDPOINTS" -> unauthScanner.scan(baseUrl);
                    default -> {
                        log.warn("Unknown scan type '{}', skipping", type);
                        yield List.of();
                    }
                };

                findings.forEach(f -> f.setJob(job));
                allFindings.addAll(findings);
                log.debug("Scan type {} completed — {} findings", type, findings.size());
            }

            findingRepository.saveAll(allFindings);
            job.setStatus(ScanJob.Status.COMPLETED);
            log.info("Scan job {} completed — {} total findings", jobId, allFindings.size());

        } catch (Exception e) {
            log.error("Scan job {} failed", jobId, e);
            job.setStatus(ScanJob.Status.FAILED);
            job.setErrorMsg(e.getMessage());
        } finally {
            job.setFinishedAt(Instant.now());
            jobRepository.save(job);
        }
    }

    public List<ScanJobResponse> listJobs(String username) {
        var user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return jobRepository.findByUserId(user.getId()).stream()
                .map(ScanJobResponse::from)
                .toList();
    }

    public ScanJobResponse getJob(Long id) {
        return ScanJobResponse.from(
                jobRepository.findById(id)
                        .orElseThrow(() -> new ResourceNotFoundException("ScanJob", id))
        );
    }

    public List<FindingResponse> getFindings(Long jobId) {
        return findingRepository.findByJobIdOrderBySeverityDesc(jobId).stream()
                .map(FindingResponse::from)
                .toList();
    }
}
