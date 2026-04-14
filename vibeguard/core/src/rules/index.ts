/**
 * VibeGuard Core — Rule Registry
 *
 * Central registry for all vulnerability detection rules.
 * Import all rules here to register them with the scanner.
 */

import { Rule } from '../types';
import sqlInjectionRule from './sql-injection';
import xssRule from './xss';
import hardcodedSecretsRule from './hardcoded-secrets';
import evalRule from './eval-usage';
import pathTraversalRule from './path-traversal';
import insecureRandomRule from './insecure-random';
import universalSecretsRule from './universal-secrets';
import pythonRules from './python-rules';
import javaRules from './java-rules';
import multiLangRules from './multi-lang-rules';

// ─── Registry ─────────────────────────────────────────────────────────────────

const RULE_REGISTRY: Rule[] = [
    sqlInjectionRule,
    xssRule,
    hardcodedSecretsRule,
    evalRule,
    pathTraversalRule,
    insecureRandomRule,
    universalSecretsRule,
    ...pythonRules,
    ...javaRules,
    ...multiLangRules,
];

/**
 * Returns all registered rules.
 */
export function getAllRules(): Rule[] {
    return [...RULE_REGISTRY];
}

/**
 * Returns a specific rule by ID.
 */
export function getRuleById(id: string): Rule | undefined {
    return RULE_REGISTRY.find((rule) => rule.id === id);
}

/**
 * Returns all rules filtered by tags.
 */
export function getRulesByTag(tag: string): Rule[] {
    return RULE_REGISTRY.filter((rule) => rule.tags.includes(tag));
}

/**
 * Returns a summary of all rules (for CLI `vibeguard rules` command).
 */
export function getRulesSummary(): Array<{
    id: string;
    name: string;
    severity: string;
    enabled: boolean;
    tags: string[];
}> {
    return RULE_REGISTRY.map((r) => ({
        id: r.id,
        name: r.name,
        severity: r.severity,
        enabled: r.enabled,
        tags: r.tags,
    }));
}
