import * as vscode from 'vscode';
import OpenAI from 'openai';
import { Vulnerability } from '@vibeguard/core';

export class OpenRouterService {
    private _client: OpenAI | null = null;
    private _fallbackModels = [
        'deepseek/deepseek-chat:free',
        'qwen/qwen3-coder:free',
        'mistralai/mistral-7b-instruct:free'
    ];

    // Fix B3: in-memory circuit breaker — don't retry models that keep failing
    private _modelFailures = new Map<string, { count: number; lastFailure: number }>();
    private readonly CIRCUIT_OPEN_THRESHOLD = 3;
    private readonly CIRCUIT_RESET_MS = 5 * 60 * 1000; // 5 minutes

    private _isCircuitOpen(model: string): boolean {
        const rec = this._modelFailures.get(model);
        if (!rec) return false;
        if (Date.now() - rec.lastFailure > this.CIRCUIT_RESET_MS) {
            this._modelFailures.delete(model);
            return false;
        }
        return rec.count >= this.CIRCUIT_OPEN_THRESHOLD;
    }

    private _recordFailure(model: string): void {
        const rec = this._modelFailures.get(model) ?? { count: 0, lastFailure: 0 };
        rec.count++;
        rec.lastFailure = Date.now();
        this._modelFailures.set(model, rec);
    }

    private _recordSuccess(model: string): void {
        this._modelFailures.delete(model);
    }

    private _initializeClient(): OpenAI {
        const config = vscode.workspace.getConfiguration('vibeguard');
        let apiKey = config.get<string>('openRouterApiKey')?.trim();
        
        if (!apiKey) {
            apiKey = process.env.OPENROUTER_API_KEY || '';
        }

        if (!apiKey) {
            throw new Error('OpenRouter API key is not configured. Please set OPENROUTER_API_KEY in environment or VS Code settings.');
        }

        return new OpenAI({
            baseURL: 'https://openrouter.ai/api/v1',
            apiKey: apiKey,
            // Allow running in VS Code environment where process.env might differ
            dangerouslyAllowBrowser: true 
        });
    }

    private get client(): OpenAI {
        if (!this._client) {
            this._client = this._initializeClient();
        }
        return this._client;
    }

    private getModel(): string {
        const config = vscode.workspace.getConfiguration('vibeguard');
        return config.get<string>('openRouterModel') || 'deepseek/deepseek-chat:free';
    }

    /**
     * Executes an AI call with fallback models support
     */
    private async executeWithFallback(messages: any[], temperature: number = 0.2): Promise<string> {
        const primaryModel = this.getModel();
        const modelsToTry = [primaryModel, ...this._fallbackModels.filter(m => m !== primaryModel)];

        let lastError: Error | null = null;

        for (const model of modelsToTry) {
            // Fix B3: skip models whose circuit is open (too many recent failures)
            if (this._isCircuitOpen(model)) continue;
            try {
                const response = await this.client.chat.completions.create({
                    model: model,
                    messages: messages,
                    temperature: temperature,
                });

                if (response.choices && response.choices.length > 0) {
                    // Fix B3: mark model as healthy on success
                    this._recordSuccess(model);
                    return response.choices[0].message.content || '';
                }
            } catch (error: any) {
                // Fix B3: record failure for circuit breaker
                this._recordFailure(model);
                lastError = error;
                console.warn(`[OpenRouter] Model ${model} failed:`, error.message);
                // Continue to the next fallback model
            }
        }

        throw new Error(`All OpenRouter models failed. Last error: ${lastError?.message}`);
    }

    /**
     * Chat with AI
     */
    public async chatWithAI(prompt: string, context: string = ''): Promise<string> {
        const messages = [
            {
                role: 'system',
                content: 'You are VibeGuard AI, an expert security assistant. Provide concise, helpful answers. Format your output using markdown. If writing code, use syntax highlighting.'
            },
            {
                role: 'user',
                content: context ? `${context}\n\nQuestion: ${prompt}` : prompt
            }
        ];

        return this.executeWithFallback(messages, 0.7);
    }

    /**
     * Explain a vulnerability
     */
    public async explainVulnerability(vuln: Vulnerability): Promise<any> {
        const prompt = `
Explain this security vulnerability in detail:
Rule ID: ${vuln.ruleId}
Severity: ${vuln.severity}
Message: ${vuln.message}
File: ${vuln.location.file}
Line: ${vuln.location.line}
Code Snippet:
\`\`\`
${(vuln as any).snippet || 'N/A'}
\`\`\`

Provide the response in the following structured format (use markdown):
### Understanding the Issue
(Explain what the vulnerability is and how it works)

### Why it's Dangerous
(Explain the potential impact)

### How to Fix
(Provide clear remediation steps)
`;
        
        const messages = [{ role: 'user', content: prompt }];
        const content = await this.executeWithFallback(messages, 0.2);
        
        return {
            id: vuln.ruleId,
            explanation: content,
            severity: vuln.severity,
            cwe: vuln.cweId || 'Unknown',
            owasp: 'Unknown'
        };
    }

    /**
     * Generate an Auto-Fix
     */
    public async autoFixCode(vuln: any, fileContent: string): Promise<any> {
        const prompt = `
You are an expert security engineer. Fix the following vulnerability in the provided code snippet.
Vulnerability: ${vuln.message}
Severity: ${vuln.severity}
Rule: ${vuln.ruleId}

Source Code Context:
\`\`\`
${fileContent}
\`\`\`

Return ONLY the complete fixed code block without any explanation. Ensure you preserve the original formatting and syntax. Do not wrap the code in markdown codeblock if the entire response is code, or if you do, ONLY provide the code block.
`;

        const messages = [{ role: 'user', content: prompt }];
        const fixedCodeRaw = await this.executeWithFallback(messages, 0.1);
        
        // Clean up markdown block if present
        let fixedCode = fixedCodeRaw.trim();
        if (fixedCode.startsWith('\`\`\`')) {
            const lines = fixedCode.split('\\n');
            lines.shift(); // remove opening
            if (lines[lines.length - 1].startsWith('\`\`\`')) {
                lines.pop(); // remove closing
            }
            fixedCode = lines.join('\\n');
        }

        return {
            fixed_code: fixedCode,
            confidence: 'high',
            explanation: 'Fixed using OpenRouter AI'
        };
    }

}

export const openRouterService = new OpenRouterService();
