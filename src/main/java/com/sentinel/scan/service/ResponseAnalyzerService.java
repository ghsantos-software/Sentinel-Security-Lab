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
import java.util.regex.Pattern;

@Service
public class ResponseAnalyzerService {

    private static final Logger log = LoggerFactory.getLogger(ResponseAnalyzerService.class);

    private static final Pattern STACK_TRACE = Pattern.compile(
            "(java\\.|org\\.springframework|at com\\.|Exception in thread|Caused by:)",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SQL_ERROR = Pattern.compile(
            "(ORA-\\d{4,}|MySQL|PostgreSQL|SQLite|JDBC|HikariCP|syntax error|PLS-\\d{4,})",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern INTERNAL_PATH = Pattern.compile(
            "(/home/|/var/|/usr/|/opt/|C:\\\\Users\\\\|C:\\\\Program|\\\\AppData\\\\)",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern SENSITIVE_FIELDS = Pattern.compile(
            "\"(password|secret|token|apiKey|api_key|privateKey|private_key|access_token)\"\\s*:",
            Pattern.CASE_INSENSITIVE
    );

    private static final List<String> ERROR_PROBE_PATHS = List.of(
            "/api/does-not-exist-12345",
            "/api/../etc/passwd",
            "/api/users/99999999",
            "/api/%00",
            "/api/login'"
    );

    private final WebClient webClient;

    public ResponseAnalyzerService(@Qualifier("scanWebClient") WebClient webClient) {
        this.webClient = webClient;
    }

    public List<ScanFinding> scan(String baseUrl) {
        List<ScanFinding> findings = new ArrayList<>();

        probeErrorResponses(baseUrl, findings);
        checkContentType(baseUrl, findings);

        return findings;
    }

    private void probeErrorResponses(String baseUrl, List<ScanFinding> findings) {
        for (String path : ERROR_PROBE_PATHS) {
            try {
                String url = baseUrl + path;

                String body = webClient.get()
                        .uri(url)
                        .exchangeToMono(r -> r.bodyToMono(String.class).defaultIfEmpty(""))
                        .block(Duration.ofSeconds(8));

                if (body == null || body.isBlank()) continue;

                if (STACK_TRACE.matcher(body).find()) {
                    findings.add(ScanFinding.builder()
                            .category("RESPONSE_ANALYSIS")
                            .severity(Severity.HIGH)
                            .title("Stack trace exposed in error response")
                            .description("The error response for '" + path + "' contains a Java stack trace. This reveals internal class names, framework versions, and application structure.")
                            .details(Map.of("url", url, "path", path, "snippet", truncate(body, 200)))
                            .build());
                }

                if (SQL_ERROR.matcher(body).find()) {
                    findings.add(ScanFinding.builder()
                            .category("RESPONSE_ANALYSIS")
                            .severity(Severity.HIGH)
                            .title("Database error details leaked")
                            .description("The response for '" + path + "' contains database-specific error messages. This can hint at SQL injection vulnerabilities and expose the DB engine.")
                            .details(Map.of("url", url, "path", path, "snippet", truncate(body, 200)))
                            .build());
                }

                if (INTERNAL_PATH.matcher(body).find()) {
                    findings.add(ScanFinding.builder()
                            .category("RESPONSE_ANALYSIS")
                            .severity(Severity.MEDIUM)
                            .title("Internal filesystem path disclosed")
                            .description("The response for '" + path + "' contains internal server paths, revealing deployment structure.")
                            .details(Map.of("url", url, "path", path, "snippet", truncate(body, 200)))
                            .build());
                }

                if (SENSITIVE_FIELDS.matcher(body).find()) {
                    findings.add(ScanFinding.builder()
                            .category("RESPONSE_ANALYSIS")
                            .severity(Severity.CRITICAL)
                            .title("Sensitive field names in response body")
                            .description("The response for '" + path + "' contains field names like 'password', 'secret', or 'token'. Sensitive data may be unintentionally exposed.")
                            .details(Map.of("url", url, "path", path, "snippet", truncate(body, 200)))
                            .build());
                }

            } catch (Exception e) {
                log.debug("Error probe {} → {}: {}", path, baseUrl, e.getMessage());
            }
        }
    }

    private void checkContentType(String baseUrl, List<ScanFinding> findings) {
        try {
            var response = webClient.get()
                    .uri(baseUrl)
                    .exchangeToMono(r -> r.toBodilessEntity())
                    .block(Duration.ofSeconds(8));

            if (response == null) return;

            var contentType = response.getHeaders().getFirst("Content-Type");
            if (contentType == null) {
                findings.add(ScanFinding.builder()
                        .category("RESPONSE_ANALYSIS")
                        .severity(Severity.LOW)
                        .title("Missing Content-Type header")
                        .description("The response has no Content-Type header. Combined with a missing X-Content-Type-Options, this may allow MIME-type sniffing.")
                        .details(Map.of("url", baseUrl))
                        .build());
            } else if (contentType.contains("text/html") && baseUrl.contains("/api/")) {
                findings.add(ScanFinding.builder()
                        .category("RESPONSE_ANALYSIS")
                        .severity(Severity.LOW)
                        .title("API endpoint returning text/html")
                        .description("An API endpoint responded with Content-Type: text/html. This may indicate an error page or misconfiguration.")
                        .details(Map.of("url", baseUrl, "content_type", contentType))
                        .build());
            }

        } catch (Exception e) {
            log.debug("Content-Type check failed for {}: {}", baseUrl, e.getMessage());
        }
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
