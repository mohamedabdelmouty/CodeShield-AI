/**
 * VibeGuard Core — AI-powered vulnerability detection
 *
 * Calls an OpenAI-compatible API to analyze code and return security findings.
 * Use with enableAi + aiEndpoint + aiApiKey in scan options.
 */

import type { Vulnerability, VulnerabilitySeverity } from './types';

const MAX_CODE_CHARS = 12000; // ~3k tokens of code to stay within context

const SYSTEM_PROMPT = `You are a security expert analyzing JavaScript/TypeScript code for vulnerabilities (e.g. injection, XSS, hardcoded secrets, insecure crypto, path traversal).
Return a JSON array of findings. Each finding must have exactly:
- "severity": one of "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
- "ruleId": string like "AI-SEC-001"
- "title": short title
- "message": description of the issue
- "line": 1-based line number (number or null if unknown)
- "remediation": how to fix it
Return only the JSON array, no markdown or extra text. If no issues, return [].`;

function buildUserPrompt(code: string, filePath: string): string {
    const truncated =
        code.length > MAX_CODE_CHARS
            ? code.slice(0, MAX_CODE_CHARS) + '\n// ... (truncated)'
            : code;
    return `Analyze this code for security vulnerabilities.\nFile: ${filePath}\n\n\`\`\`\n${truncated}\n\`\`\`\n\nReturn a JSON array of findings only.`;
}

export interface AIDetectorOptions {
    endpoint: string;
    apiKey?: string;
    model?: string;
}

interface RawFinding {
    severity?: string;
    ruleId?: string;
    title?: string;
    message?: string;
    line?: number | null;
    remediation?: string;
}

const VALID_SEVERITIES: VulnerabilitySeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function parseFindings(jsonStr: string): RawFinding[] {
    try {
        let str = jsonStr.trim();
        const match = str.match(/\[[\s\S]*\]/);
        if (match) str = match[0];
        const parsed = JSON.parse(str) as unknown;
        if (!Array.isArray(parsed)) return [];
        return parsed.filter((x): x is RawFinding => x != null && typeof x === 'object');
    } catch {
        return [];
    }
}

function toVulnerability(
    raw: RawFinding,
    filePath: string,
    id: string,
    snippet?: string
): Vulnerability {
    const severity = raw.severity && VALID_SEVERITIES.includes(raw.severity as VulnerabilitySeverity)
        ? (raw.severity as VulnerabilitySeverity)
        : 'MEDIUM';
    const line = typeof raw.line === 'number' && raw.line >= 1 ? raw.line : 1;
    return {
        id,
        ruleId: raw.ruleId ?? 'AI-SEC',
        ruleName: raw.title ?? 'AI-detected issue',
        severity,
        message: raw.message ?? '',
        description: raw.message ?? '',
        remediation: raw.remediation ?? 'Review and fix.',
        location: {
            file: filePath,
            line,
            column: 0,
            snippet: snippet ?? undefined,
        },
        aiReadyContext: { source: 'ai' },
    };
}

export async function detectWithAi(
    filePath: string,
    code: string,
    options: AIDetectorOptions,
    makeId: () => string
): Promise<Vulnerability[]> {
    const { endpoint, apiKey, model = 'gpt-4o-mini' } = options;
    const userPrompt = buildUserPrompt(code, filePath);

    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };
    if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;

    const body = {
        model,
        messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            { role: 'user', content: userPrompt },
        ],
        max_tokens: 2000,
        temperature: 0.1,
    };

    const res = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
    });

    if (!res.ok) {
        const text = await res.text();
        throw new Error(`AI API error ${res.status}: ${text.slice(0, 200)}`);
    }

    const data = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    const content = data.choices?.[0]?.message?.content ?? '';
    if (!content.trim()) return [];

    const rawFindings = parseFindings(content);
    const lines = code.split('\n');

    return rawFindings.map((raw) => {
        const line = typeof raw.line === 'number' && raw.line >= 1 ? raw.line : 1;
        const start = Math.max(0, line - 2);
        const end = Math.min(lines.length, line + 1);
        const snippet = lines.slice(start, end).join('\n');
        return toVulnerability(raw, filePath, makeId(), snippet);
    });
}
