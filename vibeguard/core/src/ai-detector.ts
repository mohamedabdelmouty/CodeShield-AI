/**
 * VibeGuard Core — AI-powered vulnerability detection
 *
 * Calls an OpenAI-compatible API to analyze code and return security findings.
 * Use with enableAi + aiEndpoint + aiApiKey in scan options.
 */

import type { Vulnerability } from './types';

const MAX_CODE_CHARS = 12000; // ~3k tokens of code to stay within context

const SYSTEM_PROMPT = `You are a security expert. You will be given a code snippet and a list of identified vulnerabilities in that code.
Your job is to provide exact remediation code (fixed code) for each vulnerability.
Return a JSON array of findings corresponding to the passed vulnerabilities.
Each finding MUST have exactly these keys:
- "id": The EXACT vulnerability ID passed to you
- "message": A deeper explanation of why this code is vulnerable
- "remediation": A short explanation of how to fix it
- "fixedCode": The exact corrected code snippet for the vulnerable lines (before/after fix comparison).
Return ONLY the JSON array, no markdown or extra text.`;

function buildUserPrompt(code: string, filePath: string, vulns: Vulnerability[]): string {
    const truncated =
        code.length > MAX_CODE_CHARS
            ? code.slice(0, MAX_CODE_CHARS) + '\n// ... (truncated)'
            : code;
            
    const vulnText = vulns.map(v => `- ID ${v.id}: ${v.ruleName} at line ${v.location.line}\n  Rule desc: ${v.description}`).join('\n');
    return `File: ${filePath}\n\nIdentified Vulnerabilities:\n${vulnText}\n\n\`\`\`\n${truncated}\n\`\`\`\n\nReturn JSON array only.`;
}

export interface AIDetectorOptions {
    endpoint: string;
    apiKey?: string;
    model?: string;
}

interface RawFinding {
    id?: string;
    message?: string;
    remediation?: string;
    fixedCode?: string;
}


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


export async function enrichWithAi(
    filePath: string,
    code: string,
    vulnerabilities: Vulnerability[],
    options: AIDetectorOptions
): Promise<Vulnerability[]> {
    if (vulnerabilities.length === 0) return [];
    
    const { endpoint, apiKey, model = 'gpt-4o-mini' } = options;
    const userPrompt = buildUserPrompt(code, filePath, vulnerabilities);

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
    if (!content.trim()) return vulnerabilities;

    const rawFindings = parseFindings(content);
    
    // Merge AI findings with the original static ones
    return vulnerabilities.map(vuln => {
        const enriched = rawFindings.find(r => r.id === vuln.id);
        if (!enriched) return vuln;
        
        return {
            ...vuln,
            message: enriched.message || vuln.message,
            remediation: enriched.remediation || vuln.remediation,
            remediationCode: enriched.fixedCode || vuln.remediationCode,
            aiReadyContext: { source: 'ai-enriched' }
        };
    });
}
