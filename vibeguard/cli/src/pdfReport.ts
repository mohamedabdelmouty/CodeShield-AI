/**
 * VibeGuard CLI — PDF report generation (no UI).
 * Writes SecurityReport to a PDF file at the given path.
 */

import { SecurityReport } from '@vibeguard/core';
import { jsPDF } from 'jspdf';
import * as fs from 'fs';

export function writePdfReport(report: SecurityReport, outputPath: string): void {
    const doc = new jsPDF();

    doc.setFontSize(22);
    doc.setTextColor(20, 20, 20);
    doc.text('VibeGuard Security Report', 14, 20);

    doc.setFontSize(10);
    doc.setTextColor(100, 100, 100);
    doc.text(`Target: ${report.target}`, 14, 28);
    doc.text(`Generated at: ${report.stats.timestamp} (v${report.version})`, 14, 34);

    doc.setDrawColor(200, 200, 200);
    doc.line(14, 40, 196, 40);

    doc.setFontSize(16);
    doc.setTextColor(40, 40, 40);
    doc.text('Summary', 14, 50);

    doc.setFontSize(12);
    const scoreColor = report.score.score >= 75 ? [40, 167, 69] : report.score.score >= 50 ? [255, 193, 7] : [220, 53, 69];
    doc.setTextColor(scoreColor[0], scoreColor[1], scoreColor[2]);
    doc.text(`Score: ${report.score.score}/100 (Grade ${report.score.grade})`, 14, 60);
    doc.setTextColor(100, 100, 100);

    const totalIssues = Object.values(report.summary).reduce((a, b) => a + b, 0);
    doc.text(`Total Vulnerabilities: ${totalIssues}`, 14, 68);
    doc.text(`Files Scanned: ${report.stats.filesScanned}`, 14, 76);

    doc.setFontSize(16);
    doc.setTextColor(40, 40, 40);
    doc.text('Findings', 14, 90);
    doc.line(14, 94, 196, 94);

    let yPos = 104;

    if (report.vulnerabilities.length === 0) {
        doc.setFontSize(12);
        doc.setTextColor(40, 167, 69);
        doc.text('No vulnerabilities detected! Great job.', 14, yPos);
    } else {
        for (const vuln of report.vulnerabilities) {
            if (yPos > 270) {
                doc.addPage();
                yPos = 20;
            }

            let sevColor: [number, number, number] = [100, 100, 100];
            if (vuln.severity === 'CRITICAL') sevColor = [255, 71, 87];
            else if (vuln.severity === 'HIGH') sevColor = [255, 107, 107];
            else if (vuln.severity === 'MEDIUM') sevColor = [255, 212, 59];
            else if (vuln.severity === 'LOW') sevColor = [116, 192, 252];

            doc.setFontSize(10);
            doc.setTextColor(sevColor[0], sevColor[1], sevColor[2]);
            doc.text(`[${vuln.severity}] ${vuln.ruleId} - ${vuln.ruleName}`, 14, yPos);

            yPos += 8;
            doc.setTextColor(80, 80, 80);

            const messageLines = doc.splitTextToSize(`Location: ${vuln.location.file}:${vuln.location.line}`, 180);
            doc.text(messageLines, 14, yPos);
            yPos += messageLines.length * 6;

            doc.setTextColor(120, 120, 120);
            const descLines = doc.splitTextToSize(`Message: ${vuln.message}`, 180);
            doc.text(descLines, 14, yPos);
            yPos += descLines.length * 6 + 6;
        }
    }

    const pdfData = doc.output('arraybuffer');
    fs.writeFileSync(outputPath, Buffer.from(pdfData));
}
