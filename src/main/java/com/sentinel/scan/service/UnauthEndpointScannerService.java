package com.sentinel.scan.service;

import com.sentinel.scan.entity.ScanFinding;
import com.sentinel.scan.entity.ScanFinding.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class UnauthEndpointScannerService {

    private static final Logger log = LoggerFactory.getLogger(UnauthEndpointScannerService.class);

    private record EndpointRule(Severity severity, String description) {}

    private static final Map<String, EndpointRule> PROBE_ENDPOINTS = new java.util.LinkedHashMap<>();

    static {
        PROBE_ENDPOINTS.put("/api/users", new EndpointRule(
                Severity.HIGH,
                "User listing is accessible without authentication. Exposes all registered users."
        ));
        PROBE_ENDPOINTS.put("/api/admin", new EndpointRule(
                Severity.CRITICAL,
                "Admin area is accessible without authentication."
        ));
        PROBE_ENDPOINTS.put("/api/admin/users", new EndpointRule(
                Severity.CRITICAL,
                "Admin user management endpoint is accessible without authentication."
        ));
        PROBE_ENDPOINTS.put("/api/config", new EndpointRule(
                Severity.HIGH,
                "Configuration endpoint is accessible without authentication. May expose environment or app settings."
        ));
        PROBE_ENDPOINTS.put("/api/settings", new EndpointRule(
                Severity.HIGH,
                "Settings endpoint is accessible without authentication."
        ));
        PROBE_ENDPOINTS.put("/api/v1/users", new EndpointRule(
                Severity.HIGH,
                "User listing (v1) is accessible without authentication."
        ));
        PROBE_ENDPOINTS.put("/api/v2/users", new EndpointRule(
                Severity.HIGH,
                "User listing (v2) is accessible without authentication."
        ));
        PROBE_ENDPOINTS.put("/api/reports", new EndpointRule(
                Severity.MEDIUM,
                "Reports endpoint is accessible without authentication."
        ));
        PROBE_ENDPOINTS.put("/api/logs", new EndpointRule(
                Severity.HIGH,
                "Logs endpoint is accessible without authentication. May expose sensitive operational data."
        ));
        PROBE_ENDPOINTS.put("/api/debug", new EndpointRule(
                Severity.CRITICAL,
                "Debug endpoint is publicly accessible. Should never be exposed in any environment."
        ));
        PROBE_ENDPOINTS.put("/console", new EndpointRule(
                Severity.CRITICAL,
                "H2/database console is publicly accessible. Provides direct database access."
        ));
        PROBE_ENDPOINTS.put("/h2-console", new EndpointRule(
                Severity.CRITICAL,
                "H2 console is publicly accessible. Full database read/write without any auth."
        ));
        PROBE_ENDPOINTS.put("/graphql", new EndpointRule(
                Severity.HIGH,
                "GraphQL endpoint is accessible without authentication. Introspection may expose the full schema."
        ));
    }

    private final WebClient webClient;

    public UnauthEndpointScannerService(@Qualifier("scanWebClient") WebClient webClient) {
        this.webClient = webClient;
    }

    public List<ScanFinding> scan(String baseUrl) {
        List<ScanFinding> findings = new ArrayList<>();
        String base = baseUrl.replaceAll("/$", "");

        for (var entry : PROBE_ENDPOINTS.entrySet()) {
            String path = entry.getKey();
            EndpointRule rule = entry.getValue();
            String url = base + path;

            try {
                var response = webClient.get()
                        .uri(url)
                        .exchangeToMono(r -> r.toBodilessEntity())
                        .block(Duration.ofSeconds(8));

                if (response == null) continue;

                int status = response.getStatusCode().value();

                if (status == 200 || status == 304) {
                    findings.add(ScanFinding.builder()
                            .category("UNAUTH_ENDPOINTS")
                            .severity(rule.severity())
                            .title("Unprotected endpoint: " + path)
                            .description(rule.description())
                            .details(Map.of("url", url, "http_status", status, "path", path))
                            .build());
                } else if (status == 401 || status == 403) {
                    findings.add(ScanFinding.builder()
                            .category("UNAUTH_ENDPOINTS")
                            .severity(Severity.INFO)
                            .title("Endpoint protected: " + path + " → " + status)
                            .description("Correctly returned HTTP " + status + " for unauthenticated request.")
                            .details(Map.of("url", url, "http_status", status, "path", path))
                            .build());
                }
                // 404 = não existe, ignora

            } catch (Exception e) {
                log.debug("Unauth probe {} at {}: {}", path, base, e.getMessage());
            }
        }

        return findings;
    }
}
