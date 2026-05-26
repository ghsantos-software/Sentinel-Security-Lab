package com.sentinel.scan.service;

import com.sentinel.scan.entity.ScanFinding;
import com.sentinel.scan.entity.ScanFinding.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class HeaderScannerService {

    private static final Logger log = LoggerFactory.getLogger(HeaderScannerService.class);

    private record HeaderRule(Severity severity, String description) {}

    private static final Map<String, HeaderRule> SECURITY_HEADERS = new LinkedHashMap<>();

    static {
        SECURITY_HEADERS.put("Strict-Transport-Security", new HeaderRule(
                Severity.HIGH,
                "HSTS not set. Clients may connect over plain HTTP and be subject to downgrade attacks."
        ));
        SECURITY_HEADERS.put("Content-Security-Policy", new HeaderRule(
                Severity.MEDIUM,
                "No CSP found. The browser has no policy to restrict resource loading, making XSS easier to exploit."
        ));
        SECURITY_HEADERS.put("X-Content-Type-Options", new HeaderRule(
                Severity.MEDIUM,
                "Missing X-Content-Type-Options: nosniff. Browsers may MIME-sniff responses and execute unexpected content."
        ));
        SECURITY_HEADERS.put("X-Frame-Options", new HeaderRule(
                Severity.MEDIUM,
                "Missing X-Frame-Options. The page can be embedded in an iframe, enabling clickjacking attacks."
        ));
        SECURITY_HEADERS.put("Referrer-Policy", new HeaderRule(
                Severity.LOW,
                "No Referrer-Policy found. Sensitive URLs may be leaked in the Referer header to third parties."
        ));
        SECURITY_HEADERS.put("Permissions-Policy", new HeaderRule(
                Severity.LOW,
                "Missing Permissions-Policy (formerly Feature-Policy). Browser features like camera and geolocation are unrestricted."
        ));
    }

    private final WebClient webClient;

    public HeaderScannerService(@Qualifier("scanWebClient") WebClient webClient) {
        this.webClient = webClient;
    }

    public List<ScanFinding> scan(String baseUrl) {
        List<ScanFinding> findings = new ArrayList<>();

        try {
            ResponseEntity<Void> response = webClient.get()
                    .uri(baseUrl)
                    .exchangeToMono(r -> r.toBodilessEntity())
                    .block(Duration.ofSeconds(12));

            if (response == null) return findings;

            var headers = response.getHeaders();

            for (var entry : SECURITY_HEADERS.entrySet()) {
                if (!headers.containsKey(entry.getKey())) {
                    findings.add(ScanFinding.builder()
                            .category("SECURITY_HEADERS")
                            .severity(entry.getValue().severity())
                            .title("Missing header: " + entry.getKey())
                            .description(entry.getValue().description())
                            .details(Map.of("header", entry.getKey(), "url", baseUrl))
                            .build());
                }
            }

            checkServerDisclosure(headers, baseUrl, findings);
            checkXPoweredBy(headers, baseUrl, findings);

        } catch (WebClientRequestException e) {
            log.warn("Header scan — could not reach {}: {}", baseUrl, e.getMessage());
            findings.add(ScanFinding.builder()
                    .category("SECURITY_HEADERS")
                    .severity(Severity.INFO)
                    .title("Target unreachable during header scan")
                    .description("Connection failed: " + e.getMessage())
                    .details(Map.of("url", baseUrl))
                    .build());
        } catch (Exception e) {
            log.error("Header scan failed for {}", baseUrl, e);
        }

        return findings;
    }

    private void checkServerDisclosure(HttpHeaders headers, String url, List<ScanFinding> findings) {
        String server = headers.getFirst("Server");
        if (server != null && server.matches(".*(Apache|nginx|IIS|Tomcat|Jetty|Undertow|Gunicorn|Kestrel)/[\\d.]+.*")) {
            findings.add(ScanFinding.builder()
                    .category("SECURITY_HEADERS")
                    .severity(Severity.LOW)
                    .title("Server version disclosed")
                    .description("O header Server expõe a versão do software (" + server + "), facilitando ataques direcionados a CVEs.")
                    .details(Map.of("header", "Server", "value", server, "url", url))
                    .build());
        }
    }

    private void checkXPoweredBy(HttpHeaders headers, String url, List<ScanFinding> findings) {
        String powered = headers.getFirst("X-Powered-By");
        if (powered != null) {
            findings.add(ScanFinding.builder()
                    .category("SECURITY_HEADERS")
                    .severity(Severity.LOW)
                    .title("X-Powered-By header presente")
                    .description("X-Powered-By expõe a tecnologia usada no backend: " + powered)
                    .details(Map.of("header", "X-Powered-By", "value", powered, "url", url))
                    .build());
        }
    }
}
