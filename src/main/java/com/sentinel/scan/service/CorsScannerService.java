package com.sentinel.scan.service;

import com.sentinel.scan.entity.ScanFinding;
import com.sentinel.scan.entity.ScanFinding.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Map;

@Service
public class CorsScannerService {

    private static final Logger log = LoggerFactory.getLogger(CorsScannerService.class);

    private final WebClient webClient;

    public CorsScannerService(@Qualifier("scanWebClient") WebClient webClient) {
        this.webClient = webClient;
    }

    public List<ScanFinding> scan(String baseUrl) {
        List<ScanFinding> findings = new ArrayList<>();

        probePreflightWildcard(baseUrl, findings);
        probeReflectedOrigin(baseUrl, findings);
        probeNullOrigin(baseUrl, findings);

        return findings;
    }

    private void probePreflightWildcard(String baseUrl, List<ScanFinding> findings) {
        try {
            ResponseEntity<Void> response = webClient.method(HttpMethod.OPTIONS)
                    .uri(baseUrl)
                    .header("Origin", "http://localhost:3000")
                    .header("Access-Control-Request-Method", "GET, POST")
                    .header("Access-Control-Request-Headers", "Authorization, Content-Type")
                    .exchangeToMono(r -> r.toBodilessEntity())
                    .block(Duration.ofSeconds(12));

            if (response == null) return;

            var headers = response.getHeaders();
            String allowOrigin = headers.getFirst("Access-Control-Allow-Origin");
            String allowCredentials = headers.getFirst("Access-Control-Allow-Credentials");

            if ("*".equals(allowOrigin)) {
                findings.add(ScanFinding.builder()
                        .category("CORS")
                        .severity(Severity.MEDIUM)
                        .title("CORS allows all origins (wildcard *)")
                        .description("Access-Control-Allow-Origin: * permits any domain to read responses. This is risky for APIs that handle authenticated data.")
                        .details(Map.of("header", "Access-Control-Allow-Origin", "value", "*", "url", baseUrl))
                        .build());
            }

            if ("*".equals(allowOrigin) && "true".equalsIgnoreCase(allowCredentials)) {
                findings.add(ScanFinding.builder()
                        .category("CORS")
                        .severity(Severity.HIGH)
                        .title("CORS wildcard with credentials — invalid and dangerous")
                        .description("Combining Allow-Origin: * with Allow-Credentials: true violates the spec. Some frameworks process it anyway, allowing cross-site credential theft.")
                        .details(Map.of(
                                "Access-Control-Allow-Origin", allowOrigin,
                                "Access-Control-Allow-Credentials", allowCredentials,
                                "url", baseUrl
                        ))
                        .build());
            }

            if (allowOrigin == null) {
                findings.add(ScanFinding.builder()
                        .category("CORS")
                        .severity(Severity.INFO)
                        .title("CORS not configured (no ACAO header)")
                        .description("The OPTIONS preflight returned no Access-Control-Allow-Origin. Cross-origin browser requests will be blocked.")
                        .details(Map.of("url", baseUrl))
                        .build());
            }

        } catch (WebClientRequestException e) {
            log.warn("CORS preflight probe failed for {}: {}", baseUrl, e.getMessage());
        } catch (Exception e) {
            log.debug("CORS wildcard probe error for {}: {}", baseUrl, e.getMessage());
        }
    }

    private void probeReflectedOrigin(String baseUrl, List<ScanFinding> findings) {
        String probeOrigin = "http://evil.example.com";
        try {
            ResponseEntity<Void> response = webClient.get()
                    .uri(baseUrl)
                    .header("Origin", probeOrigin)
                    .exchangeToMono(r -> r.toBodilessEntity())
                    .block(Duration.ofSeconds(12));

            if (response == null) return;

            String returned = response.getHeaders().getFirst("Access-Control-Allow-Origin");
            if (probeOrigin.equals(returned)) {
                String credentials = response.getHeaders().getFirst("Access-Control-Allow-Credentials");
                Severity severity = "true".equalsIgnoreCase(credentials) ? Severity.HIGH : Severity.MEDIUM;

                findings.add(ScanFinding.builder()
                        .category("CORS")
                        .severity(severity)
                        .title("Server reflects arbitrary Origin header")
                        .description("The API echoed back the attacker-controlled origin '" + probeOrigin + "'. Any domain can make credentialed cross-origin requests.")
                        .details(Map.of(
                                "probe_origin", probeOrigin,
                                "reflected_value", returned,
                                "with_credentials", credentials != null ? credentials : "not set",
                                "url", baseUrl
                        ))
                        .build());
            }

        } catch (Exception e) {
            log.debug("CORS reflected-origin probe error for {}: {}", baseUrl, e.getMessage());
        }
    }

    private void probeNullOrigin(String baseUrl, List<ScanFinding> findings) {
        try {
            ResponseEntity<Void> response = webClient.get()
                    .uri(baseUrl)
                    .header("Origin", "null")
                    .exchangeToMono(r -> r.toBodilessEntity())
                    .block(Duration.ofSeconds(12));

            if (response == null) return;

            String returned = response.getHeaders().getFirst("Access-Control-Allow-Origin");
            if ("null".equals(returned)) {
                findings.add(ScanFinding.builder()
                        .category("CORS")
                        .severity(Severity.MEDIUM)
                        .title("Server allows null Origin")
                        .description("Responding with 'null' in Access-Control-Allow-Origin enables cross-origin requests from sandboxed iframes and local HTML files.")
                        .details(Map.of("probe_origin", "null", "reflected_value", returned, "url", baseUrl))
                        .build());
            }

        } catch (Exception e) {
            log.debug("CORS null-origin probe error for {}: {}", baseUrl, e.getMessage());
        }
    }
}
