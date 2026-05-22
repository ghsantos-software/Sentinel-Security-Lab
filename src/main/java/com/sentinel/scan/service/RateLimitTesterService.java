package com.sentinel.scan.service;

import com.sentinel.scan.entity.ScanFinding;
import com.sentinel.scan.entity.ScanFinding.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimitTesterService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitTesterService.class);

    // Deliberately small — we're not fuzzing, just probing behavior
    private static final int MAX_PROBES = 12;
    private static final long DELAY_BETWEEN_REQUESTS_MS = 150;

    private final WebClient webClient;

    public RateLimitTesterService(@Qualifier("scanWebClient") WebClient webClient) {
        this.webClient = webClient;
    }

    public List<ScanFinding> scan(String baseUrl) {
        List<ScanFinding> findings = new ArrayList<>();

        probeLoginEndpoint(baseUrl, findings);
        checkRateLimitHeaders(baseUrl, findings);

        return findings;
    }

    private void probeLoginEndpoint(String baseUrl, List<ScanFinding> findings) {
        String probeUrl = baseUrl + "/api/auth/login";
        AtomicInteger successCount = new AtomicInteger(0);
        boolean rateLimitHit = false;
        String retryAfter = null;

        for (int i = 0; i < MAX_PROBES; i++) {
            try {
                Thread.sleep(DELAY_BETWEEN_REQUESTS_MS);

                var response = webClient.post()
                        .uri(probeUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{\"username\":\"__probe__\",\"password\":\"__probe__\"}")
                        .exchangeToMono(r -> r.toBodilessEntity())
                        .block(Duration.ofSeconds(8));

                if (response == null) break;

                int status = response.getStatusCode().value();

                if (status == 429) {
                    rateLimitHit = true;
                    retryAfter = response.getHeaders().getFirst("Retry-After");
                    break;
                }

                var hdrs = response.getHeaders();
                boolean hasRateLimitHeader =
                        hdrs.containsKey("X-RateLimit-Limit") ||
                        hdrs.containsKey("X-Rate-Limit-Limit") ||
                        hdrs.containsKey("RateLimit-Limit") ||
                        hdrs.containsKey("X-RateLimit-Remaining");

                if (hasRateLimitHeader) {
                    rateLimitHit = true;
                    break;
                }

                // 400/401 are expected for wrong credentials but we still increment — the point
                // is whether the server is throttling, not whether login succeeds
                if (status < 500) {
                    successCount.incrementAndGet();
                }

            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.debug("Rate limit probe {}: {}", i, e.getMessage());
            }
        }

        if (!rateLimitHit && successCount.get() >= MAX_PROBES) {
            findings.add(ScanFinding.builder()
                    .category("RATE_LIMIT")
                    .severity(Severity.MEDIUM)
                    .title("No rate limiting detected on login endpoint")
                    .description("Sent " + MAX_PROBES + " requests to the login endpoint without receiving HTTP 429 or any rate-limit response headers. The endpoint may not be protected against brute-force attacks.")
                    .details(Map.of(
                            "probe_url", probeUrl,
                            "requests_sent", MAX_PROBES,
                            "all_passed", successCount.get()
                    ))
                    .build());
        } else if (rateLimitHit) {
            findings.add(ScanFinding.builder()
                    .category("RATE_LIMIT")
                    .severity(Severity.INFO)
                    .title("Rate limiting is active on login endpoint")
                    .description("Rate limiting kicked in after " + successCount.get() + " requests. The endpoint is protected.")
                    .details(Map.of(
                            "probe_url", probeUrl,
                            "requests_before_limit", successCount.get(),
                            "retry_after", retryAfter != null ? retryAfter : "not specified"
                    ))
                    .build());
        }
    }

    private void checkRateLimitHeaders(String baseUrl, List<ScanFinding> findings) {
        try {
            var response = webClient.get()
                    .uri(baseUrl)
                    .exchangeToMono(r -> r.toBodilessEntity())
                    .block(Duration.ofSeconds(8));

            if (response == null) return;

            var headers = response.getHeaders();
            boolean hasStandardHeaders =
                    headers.containsKey("X-RateLimit-Limit") ||
                    headers.containsKey("RateLimit-Limit") ||
                    headers.containsKey("X-Rate-Limit-Limit");

            if (!hasStandardHeaders) {
                findings.add(ScanFinding.builder()
                        .category("RATE_LIMIT")
                        .severity(Severity.LOW)
                        .title("No rate limit headers on base URL")
                        .description("The API does not expose standard rate limiting headers (X-RateLimit-Limit, RateLimit-Limit). Clients have no visibility into their quota.")
                        .details(Map.of("url", baseUrl))
                        .build());
            }

        } catch (Exception e) {
            log.debug("Rate limit header check failed: {}", e.getMessage());
        }
    }
}
