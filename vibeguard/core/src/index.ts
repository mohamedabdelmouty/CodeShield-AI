/**
 * VibeGuard Core — Public API
 *
 * Main entry point. Export everything needed by CLI and VS Code extension.
 */

// Core scanning
export { scan, scanCode, VIBEGUARD_VERSION } from './scanner';

// Score engine
export { calculateSecurityScore, gradeDescription, gradeBadge } from './score';

// Reporters
export { generateTerminalReport, generateJsonReport, generateHtmlReport } from './reporter';

// Rule registry
export { getAllRules, getRuleById, getRulesByTag, getRulesSummary } from './rules';

// SCA Engine (Dependency Scanning)
export { runScaScan } from './sca-engine';
export type { ScaResult } from './sca-engine';

// Language utilities (entropy, comment-stripping)
export { shannonEntropy, isHighEntropySecret, scanExecutableLines, getExecutableLines } from './language-utils';


// Types (re-exported for consumers)
export type {
    Vulnerability,
    VulnerabilitySeverity,
    VulnerabilityLocation,
    Rule,
    RuleContext,
    ScanOptions,
    ScanStats,
    SecurityReport,
    SecurityScore,
    SecurityGrade,
    VibeGuardConfig,
} from './types';
