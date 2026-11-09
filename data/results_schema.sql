-- schema.sql - SQLite schema for prompt-injection test results & audit logs (stored in data/results.db)

-- Table that stores each test execution attempt
CREATE TABLE IF NOT EXISTS test_results (
    id TEXT NOT NULL,
    language TEXT NOT NULL,
    attack_type TEXT NOT NULL DEFAULT 'direct',      -- 'direct' or 'indirect'
    source_reference TEXT,                           -- Benchmark source (e.g., InjecAgent, MultiJail, OWASP)
    technique TEXT,                                  -- Specific attack technique/category
    prompt TEXT NOT NULL,
    injected_prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    success INTEGER NOT NULL,                        -- 1 = secret leaked, 0 = no leak, -1 = error
    private_table_accessed INTEGER NOT NULL DEFAULT 0, -- 1 = private table rows actually returned
    private_table_blocked INTEGER NOT NULL DEFAULT 0,  -- 1 = private table access blocked by ACL
    leaked_canaries TEXT,                            -- JSON array of matched canary identifiers in final output
    raw_leaked_canaries TEXT,                        -- JSON array of matched canary identifiers before output guard
    schema_disclosed TEXT,                           -- JSON array of disclosed internal/private table names
    tool_calls_json TEXT,                            -- JSON array of tool calls executed during attempt
    red_analysis TEXT,                               -- Red team analysis of previous response
    red_strategy TEXT,                               -- Red team counter-strategy used
    run_timestamp TEXT NOT NULL,                     -- ISO-8601 timestamp
    response_hash TEXT NOT NULL,
    defense_level TEXT NOT NULL DEFAULT 'off',
    attempt INTEGER NOT NULL DEFAULT 1,
    red_model TEXT,
    blue_model TEXT,
    PRIMARY KEY (id, defense_level, attempt, run_timestamp)
);

-- Simple audit log for actions performed by the agent and test harness
CREATE TABLE IF NOT EXISTS audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,                         -- ISO-8601
    details TEXT                                     -- optional free-form JSON or text
);
