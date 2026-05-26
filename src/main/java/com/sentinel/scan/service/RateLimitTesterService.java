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

@Service
public class RateLimitTesterService {

    private static final Logger log = LoggerFactory.getLogger(RateLimitTesterService.class);

    // pequeno de propósito — não é fuzzing, só verifica comportamento
    private static final int MAX_PROBES = 12;
    private static final long DELAY_MS = 150;

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
        int passed = 0;
        boolean limited = false;
        String retryAfter = null;

        for (int i = 0; i < MAX_PROBES; i++) {
            try {
                Thread.sleep(DELAY_MS);

                var response = webClient.post()
                        .uri(probeUrl)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{\"username\":\"__probe__\",\"password\":\"__probe__\"}")
                        .exchangeToMono(r -> r.toBodilessEntity())
                        .block(Duration.ofSeconds(8));

                if (response == null) break;

                int status = response.getStatusCode().value();

                if (status == 429) {
                    limited = true;
                    retryAfter = response.getHeaders().getFirst("Retry-After");
                    break;
                }

                var hdrs = response.getHeaders();
                if (hdrs.containsKey("X-RateLimit-Limit") || hdrs.containsKey("X-Rate-Limit-Limit")
                        || hdrs.containsKey("RateLimit-Limit") || hdrs.containsKey("X-RateLimit-Remaining")) {
                    limited = true;
                    break;
                }

                // 400/401 são esperados para credenciais erradas, o que interessa é se throttle acontece
                if (status < 500) {
                    passed++;
                }

            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.debug("Rate limit probe {}: {}", i, e.getMessage());
            }
        }

        if (!limited && passed >= MAX_PROBES) {
            findings.add(ScanFinding.builder()
                    .category("RATE_LIMIT")
                    .severity(Severity.MEDIUM)
                    .title("Sem rate limiting no endpoint de login")
                    .description("Enviadas " + MAX_PROBES + " requisições sem receber HTTP 429 nem headers de rate limit. O endpoint pode não ter proteção contra brute-force.")
                    .details(Map.of("probe_url", probeUrl, "requests_sent", MAX_PROBES, "all_passed", passed))
                    .build());
        } else if (limited) {
            findings.add(ScanFinding.builder()
                    .category("RATE_LIMIT")
                    .severity(Severity.INFO)
                    .title("Rate limiting ativo no endpoint de login")
                    .description("Throttle detectado após " + passed + " requisições.")
                    .details(Map.of(
                            "probe_url", probeUrl,
                            "requests_before_limit", passed,
                            "retry_after", retryAfter != null ? retryAfter : "nao informado"
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
            boolean hasHeaders = headers.containsKey("X-RateLimit-Limit")
                    || headers.containsKey("RateLimit-Limit")
                    || headers.containsKey("X-Rate-Limit-Limit");

            if (!hasHeaders) {
                findings.add(ScanFinding.builder()
                        .category("RATE_LIMIT")
                        .severity(Severity.LOW)
                        .title("Sem headers de rate limit na URL base")
                        .description("A API não retorna headers como X-RateLimit-Limit ou RateLimit-Limit. Clientes não têm visibilidade da cota.")
                        .details(Map.of("url", baseUrl))
                        .build());
            }

        } catch (Exception e) {
            log.debug("Rate limit header check falhou: {}", e.getMessage());
        }
    }
}
