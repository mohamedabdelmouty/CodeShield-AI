/**
 * VibeGuard Core — Shared Types & Interfaces
 * All type definitions used across core, CLI, and VS Code extension.
 */

// ─── Severity ────────────────────────────────────────────────────────────────

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export const SEVERITY_ORDER: Record<VulnerabilitySeverity, number> = {
    CRITICAL: 5,
    HIGH: 4,
    MEDIUM: 3,
    LOW: 2,
    INFO: 1,
};

// ─── Vulnerability ────────────────────────────────────────────────────────────

export interface VulnerabilityLocation {
    file: string;
    line: number;
    column: number;
    endLine?: number;
    endColumn?: number;
    snippet?: string;
}

export interface Vulnerability {
    id: string;
    ruleId: string;
    ruleName: string;
    severity: VulnerabilitySeverity;
    message: string;
    description: string;
    remediation: string;
    location: VulnerabilityLocation;
    cweId?: string;
    owaspCategory?: string;
    aiReadyContext?: Record<string, unknown>;
}

// ─── Rules ────────────────────────────────────────────────────────────────────

export interface RuleContext {
    filePath: string;
    fileContent: string;
    reportVulnerability: (vuln: Omit<Vulnerability, 'id' | 'location'> & { location: Omit<VulnerabilityLocation, 'file'> }) => void;
}

export interface Rule {
    id: string;
    name: string;
    description: string;
    severity: VulnerabilitySeverity;
    enabled: boolean;
    tags: string[];
    type?: 'ast' | 'text';
    check: (context: RuleContext, ast?: import('@babel/types').File | null) => void;
}

// ─── Scan Options ─────────────────────────────────────────────────────────────

export interface ScanOptions {
    /** Root directory or file to scan */
    target: string;
    /** Glob patterns to ignore */
    ignore?: string[];
    /** Specific rule IDs to run (empty = all enabled rules) */
    rules?: string[];
    /** Whether to include file content snippets in output */
    includeSnippets?: boolean;
    /** Maximum file size in bytes to scan (default: 1MB) */
    maxFileSize?: number;
    /** Enable AI-powered detection (requires aiEndpoint) */
    enableAi?: boolean;
    /** OpenAI-compatible API endpoint (e.g. https://api.openai.com/v1/chat/completions) */
    aiEndpoint?: string;
    /** API key for AI endpoint (Bearer token) */
    aiApiKey?: string;
    /** Model name for AI API (default: gpt-4o-mini) */
    aiModel?: string;
}

// ─── Security Score ───────────────────────────────────────────────────────────

export type SecurityGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface SecurityScore {
    /** Numeric score 0–100 */
    score: number;
    /** Letter grade */
    grade: SecurityGrade;
    /** Breakdown by severity */
    breakdown: Record<VulnerabilitySeverity, number>;
    /** Penalty applied */
    penalty: number;
    /** Pass/fail based on user threshold */
    passed: boolean;
}

// ─── Report ───────────────────────────────────────────────────────────────────

export interface ScanStats {
    filesScanned: number;
    filesSkipped: number;
    linesScanned: number;
    durationMs: number;
    timestamp: string;
}

export interface SecurityReport {
    /** VibeGuard version */
    version: string;
    /** Scan target */
    target: string;
    /** Overall security score */
    score: SecurityScore;
    /** All found vulnerabilities */
    vulnerabilities: Vulnerability[];
    /** Total vulnerability count by severity */
    summary: Record<VulnerabilitySeverity, number>;
    /** Scan statistics */
    stats: ScanStats;
}

// ─── Config ───────────────────────────────────────────────────────────────────

export interface VibeGuardConfig {
    /** Rules configuration */
    rules?: {
        /** Rules to disable */
        disabled?: string[];
        /** Rules to enable (overrides disabled list) */
        enabled?: string[];
        /** Override severity per rule */
        overrides?: Record<string, Partial<Pick<Rule, 'severity' | 'enabled'>>>;
    };
    /** Glob patterns to ignore during scanning */
    ignore?: string[];
    /** Minimum score to pass (0–100, default: 70) */
    threshold?: number;
    /** Default output format */
    format?: 'json' | 'terminal';
    /** Output file path for reports */
    output?: string;
    /** AI integration endpoint (future) */
    aiEndpoint?: string;
}
