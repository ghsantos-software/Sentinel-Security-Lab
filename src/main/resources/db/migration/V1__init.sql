CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    username    VARCHAR(50)  NOT NULL UNIQUE,
    email       VARCHAR(255) NOT NULL UNIQUE,
    password    VARCHAR(255) NOT NULL,
    role        VARCHAR(20)  NOT NULL DEFAULT 'USER',
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE targets (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(100)  NOT NULL,
    base_url    VARCHAR(500)  NOT NULL,
    description TEXT,
    environment VARCHAR(50)   NOT NULL DEFAULT 'LOCAL',
    active      BOOLEAN       NOT NULL DEFAULT TRUE,
    owner_id    BIGINT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMP     NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMP     NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_jobs (
    id           BIGSERIAL PRIMARY KEY,
    target_id    BIGINT       NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    requested_by BIGINT       NOT NULL REFERENCES users(id),
    status       VARCHAR(30)  NOT NULL DEFAULT 'PENDING',
    scan_types   TEXT[]       NOT NULL,
    started_at   TIMESTAMP,
    finished_at  TIMESTAMP,
    error_msg    TEXT,
    created_at   TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE scan_findings (
    id          BIGSERIAL PRIMARY KEY,
    job_id      BIGINT       NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    category    VARCHAR(50)  NOT NULL,
    severity    VARCHAR(20)  NOT NULL,
    title       VARCHAR(255) NOT NULL,
    description TEXT,
    details     JSONB,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE TABLE reports (
    id          BIGSERIAL PRIMARY KEY,
    job_id      BIGINT       NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    target_id   BIGINT       NOT NULL REFERENCES targets(id),
    generated_by BIGINT      NOT NULL REFERENCES users(id),
    summary     TEXT,
    risk_score  INTEGER,
    findings_count INTEGER,
    created_at  TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_targets_owner ON targets(owner_id);
CREATE INDEX idx_scan_jobs_target ON scan_jobs(target_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_findings_job ON scan_findings(job_id);
CREATE INDEX idx_reports_job ON reports(job_id);
