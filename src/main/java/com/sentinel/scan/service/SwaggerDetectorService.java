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
public class SwaggerDetectorService {

    private static final Logger log = LoggerFactory.getLogger(SwaggerDetectorService.class);

    private record PathRule(Severity severity, String label, String description) {}

    private static final Map<String, PathRule> PROBE_PATHS = new java.util.LinkedHashMap<>();

    static {
        PROBE_PATHS.put("/swagger-ui.html", new PathRule(
                Severity.MEDIUM, "Swagger UI",
                "Swagger UI is publicly accessible without authentication. API structure and all endpoints are exposed."
        ));
        PROBE_PATHS.put("/swagger-ui/index.html", new PathRule(
                Severity.MEDIUM, "Swagger UI (v3)",
                "Swagger UI is publicly accessible. Attackers can explore and interact with the API directly."
        ));
        PROBE_PATHS.put("/v3/api-docs", new PathRule(
                Severity.MEDIUM, "OpenAPI v3 spec",
                "The OpenAPI 3.0 JSON spec is exposed without authentication. Full API schema is readable."
        ));
        PROBE_PATHS.put("/v2/api-docs", new PathRule(
                Severity.MEDIUM, "Swagger v2 spec",
                "The Swagger 2.0 JSON spec is publicly available. Full endpoint list and model schemas are exposed."
        ));
        PROBE_PATHS.put("/api-docs", new PathRule(
                Severity.MEDIUM, "API docs endpoint",
                "An API documentation endpoint is responding publicly."
        ));
        PROBE_PATHS.put("/openapi.json", new PathRule(
                Severity.MEDIUM, "openapi.json",
                "Raw OpenAPI spec file is accessible without authentication."
        ));
        PROBE_PATHS.put("/openapi.yaml", new PathRule(
                Severity.MEDIUM, "openapi.yaml",
                "Raw OpenAPI spec file (YAML) is accessible without authentication."
        ));
        PROBE_PATHS.put("/actuator", new PathRule(
                Severity.HIGH, "Actuator root",
                "Spring Boot Actuator root is accessible. Exposes a list of all available management endpoints."
        ));
        PROBE_PATHS.put("/actuator/health", new PathRule(
                Severity.INFO, "Actuator /health",
                "The health endpoint is public. This is commonly acceptable but worth noting."
        ));
        PROBE_PATHS.put("/actuator/env", new PathRule(
                Severity.CRITICAL, "Actuator /env",
                "The /actuator/env endpoint is accessible. This can expose environment variables, configuration values, and secrets."
        ));
        PROBE_PATHS.put("/actuator/beans", new PathRule(
                Severity.HIGH, "Actuator /beans",
                "Spring Bean definitions are exposed. Reveals internal application structure."
        ));
        PROBE_PATHS.put("/actuator/mappings", new PathRule(
                Severity.HIGH, "Actuator /mappings",
                "All request mappings are exposed, giving an attacker a complete map of the application's endpoints."
        ));
        PROBE_PATHS.put("/actuator/loggers", new PathRule(
                Severity.MEDIUM, "Actuator /loggers",
                "Logger configuration is accessible and may be modifiable."
        ));
        PROBE_PATHS.put("/actuator/info", new PathRule(
                Severity.LOW, "Actuator /info",
                "App info endpoint is public. May expose build version and metadata."
        ));
    }

    private final WebClient webClient;

    public SwaggerDetectorService(@Qualifier("scanWebClient") WebClient webClient) {
        this.webClient = webClient;
    }

    public List<ScanFinding> scan(String baseUrl) {
        List<ScanFinding> findings = new ArrayList<>();
        String base = baseUrl.replaceAll("/$", "");

        for (var entry : PROBE_PATHS.entrySet()) {
            String path = entry.getKey();
            PathRule rule = entry.getValue();
            String url = base + path;

            try {
                var response = webClient.get()
                        .uri(url)
                        .exchangeToMono(r -> r.toBodilessEntity())
                        .block(Duration.ofSeconds(8));

                if (response == null) continue;

                int code = response.getStatusCode().value();
                if (code >= 200 && code < 300) {
                    findings.add(ScanFinding.builder()
                            .category("SWAGGER_DETECTION")
                            .severity(rule.severity())
                            .title(rule.label() + " exposed: " + path)
                            .description(rule.description())
                            .details(Map.of("url", url, "http_status", code, "path", path))
                            .build());
                }

            } catch (Exception e) {
                log.debug("Probe {} → {}: not accessible ({})", path, base, e.getMessage());
            }
        }

        return findings;
    }
}
