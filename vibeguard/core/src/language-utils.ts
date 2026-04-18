/**
 * VibeGuard Core — Context-Aware Language Utilities
 *
 * Provides comment-stripping and line-context utilities to prevent
 * false-positives in text-based rules (e.g. Python, Go, Ruby).
 *
 * This replaces the naive "scan every line" approach with one that
 * understands source code structure for non-JS languages.
 */

export type CommentStyle = 'hash' | 'doubleslash' | 'sql';

// ─── Comment Stripping ────────────────────────────────────────────────────────

/**
 * Returns an array of { lineNum, lineContent } for only executable lines —
 * stripping single-line comments, blank lines, and multiline string content.
 *
 * Supports Python (#), Shell (#), Ruby (#), Go (//), Java/C# (//).
 */
export function getExecutableLines(
    content: string,
    commentStyle: CommentStyle = 'hash'
): Array<{ lineNum: number; lineContent: string }> {
    const rawLines = content.split('\n');
    const executableLines: Array<{ lineNum: number; lineContent: string }> = [];

    let inMultilineString = false;
    let multilineChar = '';

    for (let i = 0; i < rawLines.length; i++) {
        let line = rawLines[i];

        // Track Python triple-quoted strings (""" or ''')
        if (commentStyle === 'hash') {
            const tripleDoubleCount = (line.match(/"""/g) || []).length;
            const tripleSingleCount = (line.match(/'''/g) || []).length;

            if (!inMultilineString && tripleDoubleCount % 2 !== 0) {
                inMultilineString = true;
                multilineChar = '"""';
            } else if (inMultilineString && multilineChar === '"""' && tripleDoubleCount % 2 !== 0) {
                inMultilineString = false;
                continue; // End of docstring
            } else if (!inMultilineString && tripleSingleCount % 2 !== 0) {
                inMultilineString = true;
                multilineChar = "'''";
            } else if (inMultilineString && multilineChar === "'''" && tripleSingleCount % 2 !== 0) {
                inMultilineString = false;
                continue;
            }

            if (inMultilineString) continue;
        }

        // Strip inline comments & blank lines
        const stripped = stripInlineComment(line, commentStyle);
        if (stripped.trim().length === 0) continue;

        executableLines.push({ lineNum: i + 1, lineContent: stripped });
    }

    return executableLines;
}

/**
 * Remove an inline comment from a line of code.
 * Handles strings correctly so it won't strip '#' inside a string value.
 */
function stripInlineComment(line: string, style: CommentStyle): string {
    const commentChar = style === 'doubleslash' ? '//' : style === 'sql' ? '--' : '#';
    let inString = false;
    let stringChar = '';

    for (let i = 0; i < line.length; i++) {
        const char = line[i];

        if (inString) {
            if (char === stringChar && line[i - 1] !== '\\') {
                inString = false;
            }
        } else {
            if (char === '"' || char === "'") {
                inString = true;
                stringChar = char;
            } else if (line.startsWith(commentChar, i)) {
                return line.substring(0, i);
            }
        }
    }
    return line;
}

// ─── Contextual Pattern Matching ──────────────────────────────────────────────

export interface CodeMatch {
    lineNum: number;
    lineContent: string;
    match: RegExpMatchArray;
}

/**
 * Scan executable lines only (no comments, no blank lines) for a pattern.
 * Returns all matches with their line numbers.
 */
export function scanExecutableLines(
    content: string,
    pattern: RegExp,
    commentStyle: CommentStyle = 'hash'
): CodeMatch[] {
    const results: CodeMatch[] = [];
    const lines = getExecutableLines(content, commentStyle);

    for (const { lineNum, lineContent } of lines) {
        const match = lineContent.match(pattern);
        if (match) {
            results.push({ lineNum, lineContent, match });
        }
    }

    return results;
}

// ─── Shannon Entropy ──────────────────────────────────────────────────────────

/**
 * Calculates Shannon entropy of a string.
 * High entropy (> 3.5) indicates random/encrypted content like API keys.
 * Low entropy (< 2.5) indicates human-readable words like "password123".
 *
 * Scale: 0 (all same chars) → ~5.5 (fully random base64)
 */
export function shannonEntropy(str: string): number {
    if (str.length === 0) return 0;

    const freq = new Map<string, number>();
    for (const char of str) {
        freq.set(char, (freq.get(char) ?? 0) + 1);
    }

    let entropy = 0;
    const len = str.length;
    for (const count of freq.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

/**
 * Returns true if a string looks like a real secret (not a placeholder).
 * Combines Shannon entropy with length and character-set checks.
 */
export function isHighEntropySecret(value: string): boolean {
    if (value.length < 12) return false;

    const entropy = shannonEntropy(value);

    // Base64-like strings: longer = lower threshold
    if (value.length >= 32 && entropy > 3.2) return true;
    if (value.length >= 20 && entropy > 3.6) return true;
    if (value.length >= 12 && entropy > 4.0) return true;

    return false;
}
