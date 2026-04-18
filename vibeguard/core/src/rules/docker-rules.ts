import { Rule, RuleContext } from '../types';

function scanLines(
    context: RuleContext,
    pattern: RegExp,
    report: (line: string, lineNum: number, match: RegExpMatchArray) => Parameters<RuleContext['reportVulnerability']>[0] | null
): void {
    if (!context.filePath.toLowerCase().includes('dockerfile')) return;
    const lines = context.fileContent.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const match = line.match(pattern);
        if (match) {
            const vuln = report(line, i + 1, match);
            if (vuln) {
                context.reportVulnerability(vuln);
            }
        }
    }
}

export const dockerRootUserRule: Rule = {
    id: 'VG-DOCKER-001',
    name: 'Docker Root User',
    description: 'Detects Docker images running as the root user by default.',
    severity: 'HIGH',
    enabled: true,
    tags: ['docker', 'iac', 'security-misconfiguration'],
    check(context: RuleContext): void {
        scanLines(context, /^USER\s+root\b/i, (_line, lineNum) => ({
            ruleId: 'VG-DOCKER-001',
            ruleName: 'Docker Root User',
            severity: 'HIGH',
            message: 'Docker Container runs as root by default.',
            description: 'Running containers as root strongly increases the impact of container escapes.',
            remediation: 'Create a dedicated non-root user and switch to it using: USER <username>',
            cweId: 'CWE-250',
            location: { line: lineNum, column: 0 },
        }));
    },
};

export const dockerLatestTagRule: Rule = {
    id: 'VG-DOCKER-002',
    name: 'Docker Latest Tag',
    description: 'Avoid using the :latest tag for base images as it can lead to unpredictable builds and supply chain risks.',
    severity: 'LOW',
    enabled: true,
    tags: ['docker', 'iac', 'supply-chain'],
    check(context: RuleContext): void {
        scanLines(context, /^FROM\s+[^\s:]+(?::latest)?(?:\s+AS\s+\w+)?$/i, (line, lineNum) => {
            // Re-check specifically for latest or MISSING tag.
            // FROM ubuntu   <- bad
            // FROM ubuntu:latest <- bad
            // FROM ubuntu:20.04 <- good
            const hasExplicitTag = line.includes(':') && !line.includes(' AS ') || (line.includes(':') && line.indexOf(':') < line.indexOf(' AS '));
            const isLatest = line.toLowerCase().includes(':latest');
            if (hasExplicitTag && !isLatest) return null as any;

            return {
                ruleId: 'VG-DOCKER-002',
                ruleName: 'Docker Latest Tag',
                severity: 'LOW',
                message: 'Base image uses :latest tag or has no tag.',
                description: 'Using :latest leads to unpredictable builds and security regressions.',
                remediation: 'Pin the base image to a specific version/digest (e.g., node:18.16.0-alpine).',
                cweId: 'CWE-1104',
                location: { line: lineNum, column: 0 },
            };
        });
    },
};

export const dockerExposeAllRule: Rule = {
    id: 'VG-DOCKER-003',
    name: 'Docker Exposes Sensitive Port',
    description: 'Detects exposing highly sensitive ports (e.g. 22 SSH) from containers.',
    severity: 'MEDIUM',
    enabled: true,
    tags: ['docker', 'iac', 'network'],
    check(context: RuleContext): void {
        scanLines(context, /^EXPOSE\s+.*?(22|23|3389|11211|6379)\b/i, (_line, lineNum, match) => ({
            ruleId: 'VG-DOCKER-003',
            ruleName: 'Docker Sensitive Port Exposed',
            severity: 'MEDIUM',
            message: `Sensitive port ${match[1]} exposed.`,
            description: `Containers should not expose administrative or unauthenticated database ports like ${match[1]} publicly.`,
            remediation: 'Remove the EXPOSE directive for this port and restrict access via Docker networks or compose.',
            cweId: 'CWE-200',
            location: { line: lineNum, column: 0 },
        }));
    },
};

export default [dockerRootUserRule, dockerLatestTagRule, dockerExposeAllRule];
