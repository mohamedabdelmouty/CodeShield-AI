import { Rule, RuleContext } from '../types';

function scanLines(
    context: RuleContext,
    pattern: RegExp,
    report: (line: string, lineNum: number, match: RegExpMatchArray) => Parameters<RuleContext['reportVulnerability']>[0] | null
): void {
    if (!context.filePath.toLowerCase().endsWith('.tf')) return;
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

export const terraformOpenS3Rule: Rule = {
    id: 'VG-TF-001',
    name: 'Terraform Public S3 Bucket',
    description: 'Detects AWS S3 buckets configured with public-read or public-read-write ACLs.',
    severity: 'CRITICAL',
    enabled: true,
    tags: ['terraform', 'iac', 'aws', 's3'],
    check(context: RuleContext): void {
        scanLines(context, /^\s*acl\s*=\s*["']public-read(-write)?["']/i, (_line, lineNum) => ({
            ruleId: 'VG-TF-001',
            ruleName: 'Terraform Public S3 Bucket',
            severity: 'CRITICAL',
            message: 'S3 bucket configured with public ACL.',
            description: 'Public S3 buckets expose sensitive data to the internet and are a leading cause of data breaches.',
            remediation: 'Change the ACL to "private" and use bucket policies to restrict access appropriately.',
            cweId: 'CWE-284',
            location: { line: lineNum, column: 0 },
        }));
    },
};

export const terraformHardcodedSecretRule: Rule = {
    id: 'VG-TF-002',
    name: 'Terraform Hardcoded AWS Credentials',
    description: 'Detects hardcoded access keys and secret keys in Terraform provider configurations.',
    severity: 'HIGH',
    enabled: true,
    tags: ['terraform', 'iac', 'aws', 'secrets'],
    check(context: RuleContext): void {
        scanLines(context, /^\s*(access_key|secret_key)\s*=\s*["'][A-Za-z0-9/+=]{10,}["']/i, (_line, lineNum) => ({
            ruleId: 'VG-TF-002',
            ruleName: 'Terraform Hardcoded AWS Credentials',
            severity: 'HIGH',
            message: 'Hardcoded AWS credential detected in Terraform file.',
            description: 'Storing credentials directly in IaC files exposes them to anyone with repository access.',
            remediation: 'Use environment variables (AWS_ACCESS_KEY_ID), IAM roles, or AWS Secrets Manager.',
            cweId: 'CWE-798',
            location: { line: lineNum, column: 0 },
        }));
    },
};

export default [terraformOpenS3Rule, terraformHardcodedSecretRule];
