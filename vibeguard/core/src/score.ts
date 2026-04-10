/**
 * VibeGuard Core — Security Score Engine
 *
 * Calculates a 0–100 security score based on vulnerability findings.
 * Each severity level carries a specific penalty weight.
 */

import {
    SecurityGrade,
    SecurityScore,
    Vulnerability,
    VulnerabilitySeverity,
} from './types';

// ─── Penalty Weights ─────────────────────────────────────────────────────────

const SEVERITY_PENALTIES: Record<VulnerabilitySeverity, number> = {
    CRITICAL: 25,
    HIGH: 15,
    MEDIUM: 8,
    LOW: 3,
    INFO: 1,
};

// ─── Grade Thresholds ─────────────────────────────────────────────────────────

function calculateGrade(score: number): SecurityGrade {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 55) return 'C';
    if (score >= 35) return 'D';
    return 'F';
}

// ─── Score Engine ─────────────────────────────────────────────────────────────

/**
 * Calculates the security score for a set of vulnerabilities.
 *
 * @param vulnerabilities - Array of found vulnerabilities
 * @param threshold - Minimum passing score (0–100), default 70
 * @param fileCount - Number of scanned files (used to normalize penalty for large codebases)
 * @returns SecurityScore object with score, grade, breakdown, and pass/fail status
 */
export function calculateSecurityScore(
    vulnerabilities: Vulnerability[],
    threshold = 70,
    fileCount = 1
): SecurityScore {
    const breakdown: Record<VulnerabilitySeverity, number> = {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0,
    };

    // Count vulnerabilities per severity
    for (const vuln of vulnerabilities) {
        breakdown[vuln.severity]++;
    }

    // Calculate raw penalty
    let rawPenalty = 0;
    for (const [severity, count] of Object.entries(breakdown) as [VulnerabilitySeverity, number][]) {
        rawPenalty += count * SEVERITY_PENALTIES[severity];
    }

    // Apply a logarithmic scale to prevent runaway penalties on large codebases.
    // The normalization factor softens the hit when many files are scanned,
    // but still tanks the score for high-density vulnerability patterns.
    const normalizationFactor = Math.max(1, Math.log10(fileCount + 1));
    const normalizedPenalty = rawPenalty / normalizationFactor;

    // Cap penalty at 100 so score never goes below 0
    const clampedPenalty = Math.min(100, normalizedPenalty);
    const score = Math.max(0, Math.round(100 - clampedPenalty));
    const grade = calculateGrade(score);

    return {
        score,
        grade,
        breakdown,
        penalty: Math.round(clampedPenalty),
        passed: score >= threshold,
    };
}

/**
 * Returns a human-readable description of the grade.
 */
export function gradeDescription(grade: SecurityGrade): string {
    const descriptions: Record<SecurityGrade, string> = {
        A: 'Excellent – Very low risk detected',
        B: 'Good – Minor issues found, review recommended',
        C: 'Fair – Moderate vulnerabilities, action required',
        D: 'Poor – Significant security issues detected',
        F: 'Critical – Immediate remediation required',
    };
    return descriptions[grade];
}

/**
 * Returns an emoji badge for the grade.
 */
export function gradeBadge(grade: SecurityGrade): string {
    const badges: Record<SecurityGrade, string> = {
        A: '🟢',
        B: '🔵',
        C: '🟡',
        D: '🟠',
        F: '🔴',
    };
    return badges[grade];
}
