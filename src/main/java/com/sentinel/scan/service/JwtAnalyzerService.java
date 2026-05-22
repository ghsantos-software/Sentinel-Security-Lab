package com.sentinel.scan.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.scan.entity.ScanFinding;
import com.sentinel.scan.entity.ScanFinding.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.*;

@Service
public class JwtAnalyzerService {

    private static final Logger log = LoggerFactory.getLogger(JwtAnalyzerService.class);

    private static final List<String> AUTH_PROBE_PATHS = List.of(
            "/api/users", "/api/user", "/api/me", "/api/profile",
            "/api/admin", "/api/admin/users", "/api/v1/users", "/api/v1/me"
    );

    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public JwtAnalyzerService(@Qualifier("scanWebClient") WebClient webClient, ObjectMapper objectMapper) {
        this.webClient = webClient;
        this.objectMapper = objectMapper;
    }

    public List<ScanFinding> scan(String baseUrl) {
        List<ScanFinding> findings = new ArrayList<>();

        checkUnauthenticatedAccess(baseUrl, findings);
        checkNoneAlgorithmAcceptance(baseUrl, findings);
        checkExpiredTokenAcceptance(baseUrl, findings);

        return findings;
    }

    private void checkUnauthenticatedAccess(String baseUrl, List<ScanFinding> findings) {
        for (String path : AUTH_PROBE_PATHS) {
            try {
                var response = webClient.get()
                        .uri(baseUrl + path)
                        .exchangeToMono(r -> r.toBodilessEntity())
                        .block(Duration.ofSeconds(8));

                if (response == null) continue;
                int status = response.getStatusCode().value();

                if (status == 200 || status == 304) {
                    findings.add(ScanFinding.builder()
                            .category("JWT_ANALYSIS")
                            .severity(Severity.HIGH)
                            .title("Unauthenticated access — " + path + " returned " + status)
                            .description("The endpoint responded successfully without any Authorization header. Authentication may not be enforced.")
                            .details(Map.of("url", baseUrl + path, "http_status", status))
                            .build());
                } else if (status == 401 || status == 403) {
                    findings.add(ScanFinding.builder()
                            .category("JWT_ANALYSIS")
                            .severity(Severity.INFO)
                            .title("Authentication enforced — " + path + " returned " + status)
                            .description("Endpoint correctly rejected an unauthenticated request with HTTP " + status + ".")
                            .details(Map.of("url", baseUrl + path, "http_status", status))
                            .build());
                    break; // one confirmation is enough
                }

            } catch (Exception e) {
                log.debug("Unauth probe {} → {}: {}", path, baseUrl, e.getMessage());
            }
        }
    }

    private void checkNoneAlgorithmAcceptance(String baseUrl, List<ScanFinding> findings) {
        String noneToken = buildToken(Map.of("alg", "none", "typ", "JWT"),
                Map.of("sub", "probe", "exp", (System.currentTimeMillis() / 1000) + 3600));

        for (String path : AUTH_PROBE_PATHS.subList(0, 3)) {
            try {
                var response = webClient.get()
                        .uri(baseUrl + path)
                        .header("Authorization", "Bearer " + noneToken)
                        .exchangeToMono(r -> r.toBodilessEntity())
                        .block(Duration.ofSeconds(8));

                if (response == null) continue;
                int status = response.getStatusCode().value();

                if (status == 200 || status == 304) {
                    findings.add(ScanFinding.builder()
                            .category("JWT_ANALYSIS")
                            .severity(Severity.CRITICAL)
                            .title("JWT 'none' algorithm accepted")
                            .description("The API accepted a JWT signed with alg=none, meaning it skips signature verification entirely. Any attacker can forge tokens.")
                            .details(Map.of("url", baseUrl + path, "token_alg", "none", "http_status", status))
                            .build());
                    return;
                }

            } catch (Exception e) {
                log.debug("None-alg probe {} → {}: {}", path, baseUrl, e.getMessage());
            }
        }
    }

    private void checkExpiredTokenAcceptance(String baseUrl, List<ScanFinding> findings) {
        // exp set 24h in the past
        String expiredToken = buildToken(
                Map.of("alg", "HS256", "typ", "JWT"),
                Map.of("sub", "probe", "iat", (System.currentTimeMillis() / 1000) - 90000,
                        "exp", (System.currentTimeMillis() / 1000) - 86400)
        );

        try {
            var response = webClient.get()
                    .uri(baseUrl + "/api/me")
                    .header("Authorization", "Bearer " + expiredToken)
                    .exchangeToMono(r -> r.toBodilessEntity())
                    .block(Duration.ofSeconds(8));

            if (response == null) return;
            int status = response.getStatusCode().value();

            if (status == 200) {
                findings.add(ScanFinding.builder()
                        .category("JWT_ANALYSIS")
                        .severity(Severity.HIGH)
                        .title("Expired JWT token accepted")
                        .description("The server accepted a token expired 24 hours ago. Expiration validation (exp claim) may not be enforced.")
                        .details(Map.of("url", baseUrl + "/api/me", "http_status", status))
                        .build());
            }

        } catch (Exception e) {
            log.debug("Expired-token probe: {}", e.getMessage());
        }
    }

    public Map<String, Object> analyzeToken(String token) {
        Map<String, Object> result = new LinkedHashMap<>();
        try {
            String[] parts = token.trim().split("\\.");
            if (parts.length < 2) {
                result.put("error", "Invalid JWT structure — expected header.payload.signature");
                return result;
            }

            Map<?, ?> header = objectMapper.readValue(
                    Base64.getUrlDecoder().decode(padBase64(parts[0])), Map.class);
            Map<?, ?> payload = objectMapper.readValue(
                    Base64.getUrlDecoder().decode(padBase64(parts[1])), Map.class);

            result.put("header", header);
            result.put("payload", payload);
            result.put("has_signature", parts.length == 3 && !parts[2].isBlank());

            List<String> warnings = new ArrayList<>();
            String alg = String.valueOf(header.get("alg"));

            if ("none".equalsIgnoreCase(alg)) {
                warnings.add("CRITICAL: alg=none — no signature, token can be forged freely");
            }
            if ("HS256".equalsIgnoreCase(alg) || "HS384".equalsIgnoreCase(alg) || "HS512".equalsIgnoreCase(alg)) {
                warnings.add("Symmetric algorithm " + alg + " — secret must be strong (≥256 bits) to resist brute-force");
            }
            if (!payload.containsKey("exp")) {
                warnings.add("No 'exp' claim — token never expires");
            } else {
                long exp = Long.parseLong(String.valueOf(payload.get("exp")));
                if (exp < System.currentTimeMillis() / 1000) {
                    warnings.add("Token is expired (exp = " + new java.util.Date(exp * 1000) + ")");
                }
            }
            if (!payload.containsKey("iss")) {
                warnings.add("No 'iss' (issuer) claim — server should validate token origin");
            }
            if (!payload.containsKey("aud")) {
                warnings.add("No 'aud' (audience) claim — token is not bound to a specific service");
            }
            if (parts.length == 2 || parts[2].isBlank()) {
                warnings.add("No signature present — this token provides zero integrity guarantee");
            }

            result.put("warnings", warnings);

        } catch (Exception e) {
            result.put("error", "Failed to decode: " + e.getMessage());
        }
        return result;
    }

    private String buildToken(Map<String, Object> header, Map<String, Object> payload) {
        try {
            String h = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(objectMapper.writeValueAsBytes(header));
            String p = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(objectMapper.writeValueAsBytes(payload));
            return h + "." + p + ".";
        } catch (Exception e) {
            return "invalid";
        }
    }

    private String padBase64(String s) {
        return s + "=".repeat((4 - s.length() % 4) % 4);
    }
}
