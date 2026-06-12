/**
 * VibeGuard Core Rules Utilities
 *
 * Common helpers for rule checking.
 */

// Fix 3: helper to check if a file path belongs to a test suite
export function isTestFile(filePath: string): boolean {
    return /\.(test|spec)\.[jt]sx?$|__tests__/.test(filePath);
}
