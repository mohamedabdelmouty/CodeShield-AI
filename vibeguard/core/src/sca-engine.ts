/**
 * VibeGuard Core — SCA (Software Composition Analysis) Engine
 *
 * Scans package.json for known vulnerable dependencies using the OSV.dev API.
 * OSV (Open Source Vulnerabilities) is a free, authoritative database backed
 * by Google, GitHub, and other major security organizations.
 *
 * API Docs: https://osv.dev/docs/
 */

import * as fs from 'fs';
import * as path from 'path';
import { Vulnerability, VulnerabilitySeverity } from './types';

// ─── OSV API Types ────────────────────────────────────────────────────────────

interface OsvQuery {
    package: { name: string; ecosystem: string };
    version: string;
}

interface OsvVuln {
    id: string;
    summary?: string;
    details?: string;
    severity?: Array<{ type: string; score: string }>;
    affected?: Array<{
        package: { name: string; ecosystem: string };
        ranges?: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>;
    }>;
    database_specific?: { severity?: string };
    references?: Array<{ type: string; url: string }>;
}

interface OsvBatchResponse {
    results: Array<{ vulns?: OsvVuln[] }>;
}

// ─── Ecosystem Detection ──────────────────────────────────────────────────────

const OSV_ENDPOINT = 'https://api.osv.dev/v1/querybatch';

/**
 * Map OSV severity definitions to VibeGuard severity levels.
 */
function mapOsvSeverity(vuln: OsvVuln): VulnerabilitySeverity {
    // CVSS-based severity from database_specific field
    const dbSev = vuln.database_specific?.severity?.toUpperCase();
    if (dbSev === 'CRITICAL') return 'CRITICAL';
    if (dbSev === 'HIGH') return 'HIGH';
    if (dbSev === 'MODERATE' || dbSev === 'MEDIUM') return 'MEDIUM';
    if (dbSev === 'LOW') return 'LOW';

    // Try CVSS score-based mapping
    if (vuln.severity?.length) {
        for (const sev of vuln.severity) {
            const score = parseFloat(sev.score);
            if (!isNaN(score)) {
                if (score >= 9.0) return 'CRITICAL';
                if (score >= 7.0) return 'HIGH';
                if (score >= 4.0) return 'MEDIUM';
                return 'LOW';
            }
        }
    }

    return 'MEDIUM'; // Default to MEDIUM when unknown
}

/**
 * Parse a package.json file and extract production + dev dependencies.
 */
function parseDependencies(pkgJsonPath: string): Array<{ name: string; version: string; ecosystem: string }> {
    try {
        const content = fs.readFileSync(pkgJsonPath, 'utf-8');
        const pkg = JSON.parse(content);

        const deps: Array<{ name: string; version: string; ecosystem: string }> = [];
        const allDeps = {
            ...(pkg.dependencies ?? {}),
            ...(pkg.devDependencies ?? {}),
            ...(pkg.peerDependencies ?? {}),
        };

        for (const [name, versionSpec] of Object.entries(allDeps)) {
            // Clean version spec: remove ^, ~, >, <, =, spaces
            const cleanVersion = String(versionSpec)
                .replace(/^[\^~>=<\s]+/, '')
                .split(' ')[0]
                .split('||')[0]
                .trim();

            if (cleanVersion && cleanVersion !== '*' && !cleanVersion.startsWith('file:')) {
                deps.push({ name, version: cleanVersion, ecosystem: 'npm' });
            }
        }

        return deps;
    } catch {
        return [];
    }
}

/**
 * Query OSV.dev batch API for known vulnerabilities.
 */
async function queryOsvBatch(queries: OsvQuery[]): Promise<OsvBatchResponse> {
    const body = JSON.stringify({ queries });

    const response = await fetch(OSV_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        signal: AbortSignal.timeout(15000), // 15s timeout
    });

    if (!response.ok) {
        throw new Error(`OSV API returned ${response.status}: ${response.statusText}`);
    }

    return response.json() as Promise<OsvBatchResponse>;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface ScaResult {
    packageFile: string;
    vulnerabilities: Vulnerability[];
}

let _scaVulnCounter = 90000; // separate counter space from code vulns

function makeScaVulnId(): string {
    return `VG-SCA-${String(++_scaVulnCounter).padStart(5, '0')}`;
}

/**
 * Scan a directory for package.json files and check dependencies against OSV.dev.
 * Returns a list of dependency vulnerabilities.
 */
export async function runScaScan(targetDir: string): Promise<ScaResult[]> {
    const results: ScaResult[] = [];

    // Find all package.json files (not inside node_modules)
    const pkgFiles = findPackageJsonFiles(targetDir);

    if (pkgFiles.length === 0) {
        return results;
    }

    for (const pkgFile of pkgFiles) {
        const deps = parseDependencies(pkgFile);
        if (deps.length === 0) continue;

        try {
            const queries: OsvQuery[] = deps.map(d => ({
                package: { name: d.name, ecosystem: d.ecosystem },
                version: d.version,
            }));

            // OSV accepts max 1000 queries per batch - chunk if needed
            const BATCH_SIZE = 100;
            const allVulns: Vulnerability[] = [];

            for (let i = 0; i < queries.length; i += BATCH_SIZE) {
                const chunk = queries.slice(i, i + BATCH_SIZE);
                const chunkDeps = deps.slice(i, i + BATCH_SIZE);

                const response = await queryOsvBatch(chunk);

                for (let j = 0; j < response.results.length; j++) {
                    const result = response.results[j];
                    const dep = chunkDeps[j];

                    if (!result.vulns || result.vulns.length === 0) continue;

                    for (const vuln of result.vulns) {
                        const severity = mapOsvSeverity(vuln);
                        const fixedVersion = getFixedVersion(vuln);

                        allVulns.push({
                            id: makeScaVulnId(),
                            ruleId: 'VG-SCA-001',
                            ruleName: 'Vulnerable Dependency',
                            severity,
                            message: `${dep.name}@${dep.version} has a known vulnerability: ${vuln.id}`,
                            description: vuln.summary
                                ?? vuln.details?.substring(0, 250)
                                ?? `Vulnerability ${vuln.id} affects ${dep.name}.`,
                            remediation: fixedVersion
                                ? `Upgrade ${dep.name} to version ${fixedVersion} or later.`
                                : `Review and update ${dep.name}. Check OSV for details: https://osv.dev/vulnerability/${vuln.id}`,
                            cweId: 'CWE-1104',
                            owaspCategory: 'A06:2021 – Vulnerable and Outdated Components',
                            location: {
                                file: pkgFile,
                                line: 1,
                                column: 0,
                                snippet: `"${dep.name}": "${dep.version}"`,
                            },
                        });
                    }
                }
            }

            if (allVulns.length > 0) {
                results.push({ packageFile: pkgFile, vulnerabilities: allVulns });
            }
        } catch (err) {
            console.warn(`[VibeGuard SCA] Failed to scan ${pkgFile}: ${err instanceof Error ? err.message : String(err)}`);
        }
    }

    return results;
}

/**
 * Extract the "fixed" version from OSV vulnerability data.
 */
function getFixedVersion(vuln: OsvVuln): string | null {
    try {
        for (const aff of (vuln.affected ?? [])) {
            for (const range of (aff.ranges ?? [])) {
                for (const event of range.events) {
                    if (event.fixed) return event.fixed;
                }
            }
        }
    } catch { /* ignore */ }
    return null;
}

/**
 * Find all package.json files in a directory, excluding node_modules.
 */
function findPackageJsonFiles(dir: string): string[] {
    const results: string[] = [];

    function walk(currentDir: string, depth: number) {
        if (depth > 4) return; // Don't go too deep
        let entries: fs.Dirent[];
        try {
            entries = fs.readdirSync(currentDir, { withFileTypes: true });
        } catch {
            return;
        }

        for (const entry of entries) {
            const fullPath = path.join(currentDir, entry.name);
            if (entry.isDirectory()) {
                if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') {
                    continue; // Skip these directories
                }
                walk(fullPath, depth + 1);
            } else if (entry.isFile() && entry.name === 'package.json') {
                results.push(fullPath);
            }
        }
    }

    // Only walk if dir exists and is a directory
    try {
        if (fs.statSync(dir).isDirectory()) {
            walk(dir, 0);
        }
    } catch { /* ignore */ }

    return results;
}
