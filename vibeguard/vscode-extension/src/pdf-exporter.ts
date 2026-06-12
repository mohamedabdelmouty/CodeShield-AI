import * as vscode from 'vscode';
import { SecurityReport } from '@vibeguard/core';
import { jsPDF } from 'jspdf';
import * as fs from 'fs';

function buildPdfBuffer(report: SecurityReport): Buffer {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
    const W = 210; // A4 width
    const MARGIN = 14;
    const CONTENT_W = W - MARGIN * 2;
    let y = 0;

    // ── Helper: add new page if needed ──────────────────────────────────
    function checkPage(needed: number) {
        if (y + needed > 280) { doc.addPage(); y = 20; }
    }

    // ── COVER HEADER ────────────────────────────────────────────────────
    doc.setFillColor(79, 70, 229); // indigo
    doc.rect(0, 0, W, 45, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('VibeGuard Security Report', MARGIN, 22);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text(`Target: ${report.target}`, MARGIN, 32);
    doc.text(`Generated: ${new Date(report.stats.timestamp).toLocaleString()}  |  v${report.version}`, MARGIN, 38);
    y = 58;

    // ── SCORE CARD ───────────────────────────────────────────────────────
    const scoreColors: Record<string, [number, number, number]> = {
        A: [34, 197, 94], B: [74, 222, 128], C: [250, 204, 21],
        D: [251, 146, 60], F: [239, 68, 68],
    };
    const sc = scoreColors[report.score.grade] ?? [156, 163, 175];
    doc.setFillColor(...sc);
    doc.roundedRect(MARGIN, y, 55, 30, 3, 3, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    doc.text(`${report.score.score}`, MARGIN + 8, y + 16);
    doc.setFontSize(11);
    doc.text(`Grade: ${report.score.grade}`, MARGIN + 8, y + 25);

    // Stats on the right
    doc.setTextColor(60, 60, 60);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    const statsX = MARGIN + 65;
    doc.text(`Files Scanned: ${report.stats.filesScanned}`, statsX, y + 8);
    doc.text(`Lines of Code: ${report.stats.linesScanned?.toLocaleString() ?? '-'}`, statsX, y + 15);
    doc.text(`Duration: ${((report.stats.durationMs ?? 0) / 1000).toFixed(1)}s`, statsX, y + 22);
    doc.text(`Total Issues: ${report.vulnerabilities.length}`, statsX, y + 29);
    y += 42;

    // ── SEVERITY SUMMARY BAR ─────────────────────────────────────────────
    doc.setFillColor(249, 250, 251);
    doc.roundedRect(MARGIN, y, CONTENT_W, 22, 2, 2, 'F');
    const sevs = [
        { label: 'CRITICAL', color: [239, 68, 68] as [number, number, number], key: 'CRITICAL' },
        { label: 'HIGH',     color: [249, 115, 22] as [number, number, number], key: 'HIGH' },
        { label: 'MEDIUM',   color: [234, 179, 8] as [number, number, number], key: 'MEDIUM' },
        { label: 'LOW',      color: [59, 130, 246] as [number, number, number], key: 'LOW' },
        { label: 'INFO',     color: [107, 114, 128] as [number, number, number], key: 'INFO' },
    ];
    const boxW = CONTENT_W / sevs.length;
    sevs.forEach((s, i) => {
        const bx = MARGIN + i * boxW;
        doc.setFillColor(...s.color);
        doc.circle(bx + 6, y + 11, 3, 'F');
        doc.setTextColor(40, 40, 40);
        doc.setFontSize(9);
        doc.setFont('helvetica', 'bold');
        doc.text(String(report.summary[s.key as keyof typeof report.summary] ?? 0), bx + 11, y + 12);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(100, 100, 100);
        doc.text(s.label, bx + 11, y + 18);
    });
    y += 32;

    // ── VULNERABILITY FINDINGS ───────────────────────────────────────────
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(30, 30, 30);
    doc.text('Vulnerability Findings', MARGIN, y);
    y += 8;
    doc.setDrawColor(79, 70, 229);
    doc.setLineWidth(0.5);
    doc.line(MARGIN, y, W - MARGIN, y);
    y += 8;

    if (report.vulnerabilities.length === 0) {
        doc.setFontSize(12);
        doc.setTextColor(34, 197, 94);
        doc.setFont('helvetica', 'normal');
        doc.text('No vulnerabilities detected \u2014 excellent security posture!', MARGIN, y);
    } else {
        for (const vuln of report.vulnerabilities) {
            checkPage(40);
            const sevColorMap: Record<string, [number, number, number]> = {
                CRITICAL: [239, 68, 68], HIGH: [249, 115, 22],
                MEDIUM: [234, 179, 8], LOW: [59, 130, 246], INFO: [107, 114, 128],
            };
            const sc2 = sevColorMap[vuln.severity] ?? [107, 114, 128];

            // Card background
            doc.setFillColor(250, 250, 252);
            doc.setDrawColor(230, 230, 240);
            doc.setLineWidth(0.3);
            doc.roundedRect(MARGIN, y, CONTENT_W, 2, 1, 1, 'FD');

            // Severity badge
            doc.setFillColor(...sc2);
            doc.roundedRect(MARGIN, y, 22, 7, 1, 1, 'F');
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(7);
            doc.setFont('helvetica', 'bold');
            doc.text(vuln.severity, MARGIN + 2, y + 5);

            // Rule name
            doc.setTextColor(20, 20, 20);
            doc.setFontSize(10);
            doc.setFont('helvetica', 'bold');
            doc.text(vuln.ruleName ?? vuln.ruleId, MARGIN + 26, y + 5);

            // Rule ID tag
            doc.setFillColor(241, 240, 255);
            doc.setTextColor(79, 70, 229);
            doc.setFontSize(7);
            doc.setFont('helvetica', 'normal');
            doc.text(vuln.ruleId, W - MARGIN - 2, y + 5, { align: 'right' });
            y += 10;

            // Location
            doc.setFillColor(245, 245, 245);
            doc.roundedRect(MARGIN, y, CONTENT_W, 6, 1, 1, 'F');
            doc.setTextColor(80, 80, 80);
            doc.setFontSize(8);
            const locText = `${vuln.location.file}:${vuln.location.line}`;
            const locLines = doc.splitTextToSize(locText, CONTENT_W - 4);
            doc.text(locLines[0], MARGIN + 2, y + 4);
            y += 8;

            // Message
            doc.setTextColor(55, 65, 81);
            doc.setFontSize(9);
            doc.setFont('helvetica', 'normal');
            const msgLines = doc.splitTextToSize(vuln.message, CONTENT_W);
            checkPage(msgLines.length * 5 + 20);
            doc.text(msgLines, MARGIN, y);
            y += msgLines.length * 5 + 4;

            // Remediation
            if (vuln.remediation) {
                doc.setFillColor(236, 253, 245);
                const remLines = doc.splitTextToSize(`Remediation: ${vuln.remediation}`, CONTENT_W - 8);
                checkPage(remLines.length * 5 + 10);
                doc.roundedRect(MARGIN, y, CONTENT_W, remLines.length * 5 + 6, 2, 2, 'F');
                doc.setTextColor(6, 95, 70);
                doc.setFontSize(8);
                doc.text(remLines, MARGIN + 4, y + 5);
                y += remLines.length * 5 + 10;
            } else {
                y += 6;
            }

            // Divider
            doc.setDrawColor(230, 230, 240);
            doc.setLineWidth(0.2);
            doc.line(MARGIN, y, W - MARGIN, y);
            y += 6;
        }
    }

    // ── FOOTER on every page ─────────────────────────────────────────────
    const totalPages = (doc as any).internal.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
        doc.setPage(i);
        doc.setFillColor(245, 245, 250);
        doc.rect(0, 287, W, 10, 'F');
        doc.setTextColor(150, 150, 150);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'normal');
        doc.text('VibeGuard Security Report \u2014 Confidential', MARGIN, 293);
        doc.text(`Page ${i} of ${totalPages}`, W - MARGIN, 293, { align: 'right' });
    }

    return Buffer.from(doc.output('arraybuffer'));
}

export function exportToPdfToPath(report: SecurityReport, outputPath: string): void {
    const buffer = buildPdfBuffer(report);
    fs.writeFileSync(outputPath, buffer);
}

export async function exportToPdf(report: SecurityReport): Promise<void> {
    try {
        const defaultUri = vscode.Uri.file(
            vscode.workspace.workspaceFolders?.[0]?.uri.fsPath
                ? `${vscode.workspace.workspaceFolders[0].uri.fsPath}/vibeguard-report.pdf`
                : 'vibeguard-report.pdf'
        );

        const saveUri = await vscode.window.showSaveDialog({
            defaultUri,
            filters: { 'PDF files': ['pdf'] },
            title: 'Save VibeGuard Security Report'
        });

        if (!saveUri) return;

        await vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Generating VibeGuard PDF Report...',
            cancellable: false
        }, async () => {
            exportToPdfToPath(report, saveUri.fsPath);
            vscode.window.showInformationMessage(`VibeGuard: Successfully exported report to ${saveUri.fsPath}`);
        });
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        vscode.window.showErrorMessage(`VibeGuard: Failed to generate PDF - ${message}`);
    }
}
