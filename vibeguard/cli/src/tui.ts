/**
 * VibeGuard TUI — Interactive Terminal Dashboard
 * 
 * A full-screen interactive dashboard using ANSI escape codes and readline.
 */

import { SecurityReport } from '@vibeguard/core';
import * as readline from 'readline';

export async function runTuiDashboard(report: SecurityReport) {
    const { vulnerabilities, score, stats, target } = report;
    const { default: chalk } = await import('chalk');

    // Clean screen and enter alternate buffer
    process.stdout.write('\x1b[?1049h');
    process.stdout.write('\x1b[2J\x1b[H');

    let selectedIndex = 0;
    const totalLines = vulnerabilities.length;

    function render() {
        // Move to top
        process.stdout.write('\x1b[H');

        // Header
        console.log(chalk.bold.bgCyan.black(`  🛡️  VibeGuard Interactive Dashboard — v${report.version}  `));
        console.log(chalk.dim(`  Target: ${target}`));
        console.log('');

        // Score Panel
        const scoreColor = score.passed ? chalk.green : chalk.red;
        console.log(`  ${chalk.bold('Security Score:')} ${scoreColor(score.score + '/100')}  [${score.grade}]`);
        console.log(`  ${chalk.bold('Issues:')} ${vulnerabilities.length} (${stats.filesScanned} files scanned)`);
        console.log(chalk.dim('  ' + '─'.repeat(process.stdout.columns - 4)));

        // Vulnerability List
        if (vulnerabilities.length === 0) {
            console.log(chalk.green('\n   ✅ No vulnerabilities found. Your code vibes are immaculate!'));
        } else {
            console.log(chalk.bold('  Detected Vulnerabilities (Use ↑/↓ to navigate):'));
            vulnerabilities.forEach((v, i) => {
                const prefix = i === selectedIndex ? chalk.cyan('  ▶ ') : '    ';
                const color = i === selectedIndex ? chalk.white : chalk.dim;
                const sevColor = v.severity === 'CRITICAL' ? chalk.red : v.severity === 'HIGH' ? chalk.redBright : chalk.yellow;

                console.log(`${prefix}${sevColor(`[${v.severity.padEnd(8)}]`)} ${color(v.ruleName)} ${chalk.dim(`(${v.location.file.split(/[\\/]/).pop()}:${v.location.line})`)}`);
            });
        }

        // Details Panel (Bottom)
        if (vulnerabilities.length > 0) {
            console.log('\n' + chalk.dim('  ' + '─'.repeat(process.stdout.columns - 4)));
            const selected = vulnerabilities[selectedIndex];
            console.log(chalk.bold(`  Details for: ${chalk.cyan(selected.id)}`));
            console.log(`  ${chalk.bold('Message:')}     ${selected.message}`);
            console.log(`  ${chalk.bold('Remediation:')} ${chalk.green(selected.remediation)}`);
            if (selected.location.snippet) {
                console.log(chalk.dim('\n  Snippet:'));
                selected.location.snippet.split('\n').forEach(line => {
                    console.log(`  ${chalk.bgBlack.gray('  │  ')} ${line}`);
                });
            }
        }

        // Help
        process.stdout.write('\x1b[?25l'); // Hide cursor
        console.log(`\n  ${chalk.bgWhite.black(' q ')} Quit  ${chalk.bgWhite.black(' ↑/↓ ')} Navigate`);
    }

    render();

    readline.emitKeypressEvents(process.stdin);
    if (process.stdin.isTTY) process.stdin.setRawMode(true);

    return new Promise<void>((resolve) => {
        process.stdin.on('keypress', (_, key) => {
            if (key.name === 'q' || (key.ctrl && key.name === 'c')) {
                process.stdin.setRawMode(false);
                process.stdout.write('\x1b[?1049l'); // Exit alternate buffer
                process.stdout.write('\x1b[?25h'); // Show cursor
                resolve();
            } else if (key.name === 'up') {
                selectedIndex = Math.max(0, selectedIndex - 1);
                process.stdout.write('\x1b[2J\x1b[H'); // Clear
                render();
            } else if (key.name === 'down') {
                selectedIndex = Math.min(totalLines - 1, selectedIndex + 1);
                process.stdout.write('\x1b[2J\x1b[H'); // Clear
                render();
            }
        });
    });
}
