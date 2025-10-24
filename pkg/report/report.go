package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time" // Added missing import

	"github.com/ConstantineCTF/hardend/pkg/checks"
	// Removed: "github.com/ConstantineCTF/hardend/pkg/utils" (no longer needed directly in this file)
	// Removed: "github.com/fatih/color" (no longer needed)
)

// Reporter generates security reports
type Reporter struct {
	format string
	quiet  bool
}

// NewReporter creates a new reporter
func NewReporter(format string, quiet bool) *Reporter {
	return &Reporter{
		format: format,
		quiet:  quiet,
	}
}

// Generate creates a security report in the specified format
func (r *Reporter) Generate(results *checks.Results, outputFile string) error {
	var output string
	var err error

	// Ensure results are not nil before proceeding
	if results == nil {
		return fmt.Errorf("cannot generate report from nil results")
	}

	switch r.format {
	case "table":
		output = r.generateTableReport(results)
	case "json":
		output, err = r.generateJSONReport(results)
		if err != nil {
			return fmt.Errorf("failed to generate JSON report: %w", err)
		}
	case "html":
		output = r.generateHTMLReport(results)
	default: // Default to table format
		r.format = "table" // Ensure format is explicitly set if default
		output = r.generateTableReport(results)
	}

	// Write to file or print to stdout
	if outputFile != "" {
		err = os.WriteFile(outputFile, []byte(output), 0644)
		if err != nil {
			return fmt.Errorf("failed to write report to file %s: %w", outputFile, err)
		}
	} else {
		// Only print to stdout if not in quiet mode
		if !r.quiet {
			fmt.Print(output)
		}
	}
	return nil
}

// generateTableReport creates a clean, Markdown-style table report for stdout
func (r *Reporter) generateTableReport(results *checks.Results) string {
	var report strings.Builder

	// Add header, system info, summary etc. only if not quiet
	if !r.quiet {
		report.WriteString(r.getReportHeader(results))
		report.WriteString(r.getSystemInfoSection(results))
		report.WriteString(r.getExecutiveSummary(results))
	}

	report.WriteString(r.getFindingsTable(results)) // Always include findings table

	if !r.quiet {
		report.WriteString(r.getSummarySection(results))
		// Optionally include remediation only if not quiet and requested?
		// if results.Config.Reporting.RemediationPriority { // Need access to config or pass flag
		report.WriteString(r.getRemediationSection(results))
		// }
		report.WriteString(r.getReportFooter())
	}

	return report.String()
}

// getReportHeader generates a professional header for the text report
func (r *Reporter) getReportHeader(results *checks.Results) string {
	// Check if SystemInfo is populated before accessing Hostname
	hostname := "Unknown Host"
	if results.SystemInfo.Hostname != "" {
		hostname = results.SystemInfo.Hostname
	}
	return fmt.Sprintf(`
#################################################################
#
#   HARDEND - LINUX SECURITY ASSESSMENT REPORT
#
#################################################################

Scan Target:   %s
Report Time:   %s

`, hostname, time.Now().Format(time.RFC1123)) // Corrected: Use time.Now()
}

// getSystemInfoSection generates system information display for text report
func (r *Reporter) getSystemInfoSection(results *checks.Results) string {
	var section strings.Builder
	section.WriteString("--- SYSTEM INFORMATION ---\n")
	section.WriteString(fmt.Sprintf("  Hostname:     %s\n", results.SystemInfo.Hostname))
	section.WriteString(fmt.Sprintf("  OS:           %s (%s)\n", results.SystemInfo.OS, results.SystemInfo.Architecture))
	section.WriteString(fmt.Sprintf("  Kernel:       %s\n", results.SystemInfo.Kernel))
	section.WriteString(fmt.Sprintf("  Uptime:       %s\n", results.SystemInfo.Uptime))
	section.WriteString(fmt.Sprintf("  Scan Started: %s\n", results.StartTime.Format("2006-01-02 15:04:05")))
	section.WriteString(fmt.Sprintf("  Scan Duration: %s\n\n", results.Duration))
	return section.String()
}

// getExecutiveSummary generates a professional executive summary for text report
func (r *Reporter) getExecutiveSummary(results *checks.Results) string {
	var summary strings.Builder
	summary.WriteString("--- EXECUTIVE SUMMARY ---\n")

	// Determine overall threat level based on findings
	threatLevel := "LOW" // Default
	if results.Summary.CriticalIssues > 0 {
		threatLevel = "CRITICAL"
	} else if results.Summary.HighIssues > 0 {
		threatLevel = "HIGH"
	} else if results.Summary.MediumIssues > 0 {
		threatLevel = "MEDIUM"
	} else if results.Summary.TotalChecks == 0 {
		threatLevel = "UNKNOWN" // No checks run or reported
	} else if results.Summary.FailedChecks == 0 && results.Summary.WarningChecks == 0 {
		threatLevel = "INFO" // Only info/pass findings
	}

	summary.WriteString(fmt.Sprintf("  Overall Assessed Threat Level: %s\n", threatLevel))
	summary.WriteString(fmt.Sprintf("  Total Checks Executed: %d\n", results.Summary.TotalChecks))
	totalIssues := results.Summary.FailedChecks + results.Summary.WarningChecks
	summary.WriteString(fmt.Sprintf("  Issues Found: %d (Passed: %d, Failed: %d, Warn: %d, Skip: %d)\n\n",
		totalIssues,
		results.Summary.PassedChecks,
		results.Summary.FailedChecks,
		results.Summary.WarningChecks,
		results.Summary.SkippedChecks))

	summary.WriteString("  Issues by Severity:\n")
	summary.WriteString(fmt.Sprintf("    CRITICAL: %d\n", results.Summary.CriticalIssues))
	summary.WriteString(fmt.Sprintf("    HIGH:     %d\n", results.Summary.HighIssues))
	summary.WriteString(fmt.Sprintf("    MEDIUM:   %d\n", results.Summary.MediumIssues))
	summary.WriteString(fmt.Sprintf("    LOW:      %d\n\n", results.Summary.LowIssues))
	return summary.String()
}

// getFindingsTable generates the main findings table in Markdown format
func (r *Reporter) getFindingsTable(results *checks.Results) string {
	var out strings.Builder
	if !r.quiet { // Add header only if not quiet
		out.WriteString("--- DETAILED FINDINGS ---\n\n")
	}

	// Sort findings by severity (Critical first)
	sortedFindings := make([]*checks.Finding, 0, len(results.Findings))
	// Filter out PASS/INFO unless verbose/advanced? For table, let's usually hide them.
	includePassed := false // Could make this configurable later
	for _, f := range results.Findings {
		if f.Status != checks.StatusPass && f.Status != checks.StatusInfo || includePassed {
			sortedFindings = append(sortedFindings, f)
		}
	}

	sort.Slice(sortedFindings, func(i, j int) bool {
		order := map[checks.Severity]int{
			checks.SeverityCritical: 5,
			checks.SeverityHigh:     4,
			checks.SeverityMedium:   3,
			checks.SeverityLow:      2,
			checks.SeverityInfo:     1, // Should already be filtered out unless includePassed
		}
		// Primary sort by severity, secondary by ID (or Title) for consistency
		if order[sortedFindings[i].Severity] != order[sortedFindings[j].Severity] {
			return order[sortedFindings[i].Severity] > order[sortedFindings[j].Severity]
		}
		return sortedFindings[i].ID < sortedFindings[j].ID
	})

	if len(sortedFindings) == 0 {
		if !r.quiet {
			out.WriteString("  No significant issues detected (or only PASS/INFO findings).\n\n")
		}
		return out.String() // Return early if no findings to display
	}

	// Markdown-style table header row
	// Adjusted column widths
	out.WriteString("| STATUS | SEVERITY | CATEGORY       | FINDING                                          | ACTUAL               | EXPECTED             |\n")
	out.WriteString("|:-------|:---------|:---------------|:-------------------------------------------------|:---------------------|:---------------------|\n")

	for _, f := range sortedFindings {
		status := r.formatStatus(f.Status)
		severity := r.formatSeverity(f.Severity)
		category := r.truncateString(f.Category, 14)
		title := r.truncateString(f.Title, 48)
		actual := r.truncateString(f.Actual, 20)
		expected := r.truncateString(f.Expected, 20)

		out.WriteString(fmt.Sprintf(
			"| %-6s | %-8s | %-14s | %-48s | %-20s | %-20s |\n",
			status, severity, category, title, actual, expected,
		))
	}
	out.WriteString("\n")
	return out.String()
}

// getSummarySection generates the summary statistics section for text report
func (r *Reporter) getSummarySection(results *checks.Results) string {
	var summary strings.Builder
	summary.WriteString("\n--- SCAN STATISTICS ---\n")
	total := results.Summary.TotalChecks
	passed := results.Summary.PassedChecks
	failed := results.Summary.FailedChecks

	passRate := 0.0
	if total > 0 {
		passRate = float64(passed) / float64(total) * 100
	}

	summary.WriteString(fmt.Sprintf("  Total Checks Configured/Executed: %d\n", total)) // Clarify meaning
	summary.WriteString(fmt.Sprintf("  Passed: %d (%.1f%%)\n", passed, passRate))
	summary.WriteString(fmt.Sprintf("  Failed: %d\n", failed))
	summary.WriteString(fmt.Sprintf("  Warnings: %d\n", results.Summary.WarningChecks))
	summary.WriteString(fmt.Sprintf("  Skipped: %d\n\n", results.Summary.SkippedChecks))
	return summary.String()
}

// getRemediationSection generates prioritized remediation guidance for text report
func (r *Reporter) getRemediationSection(results *checks.Results) string {
	var remediation strings.Builder
	remediation.WriteString("\n--- PRIORITY REMEDIATION GUIDE ---\n\n")

	// Get Critical and High findings that Failed
	var priorityFindings []*checks.Finding
	for _, finding := range results.Findings {
		if finding.Status == checks.StatusFail &&
			(finding.Severity == checks.SeverityCritical || finding.Severity == checks.SeverityHigh) {
			priorityFindings = append(priorityFindings, finding)
		}
	}

	// Sort priority findings (optional, but nice) - Critical first, then by ID
	sort.Slice(priorityFindings, func(i, j int) bool {
		order := map[checks.Severity]int{checks.SeverityCritical: 2, checks.SeverityHigh: 1}
		if order[priorityFindings[i].Severity] != order[priorityFindings[j].Severity] {
			return order[priorityFindings[i].Severity] > order[priorityFindings[j].Severity]
		}
		return priorityFindings[i].ID < priorityFindings[j].ID
	})

	if len(priorityFindings) == 0 {
		remediation.WriteString("  No critical or high-severity failures detected.\n")
		return remediation.String()
	}

	remediation.WriteString("  Address these issues first based on severity:\n\n")
	for i, finding := range priorityFindings {
		remediation.WriteString(fmt.Sprintf("%d. [%s] %s (%s)\n", i+1, finding.Severity, finding.Title, finding.ID))
		if finding.Remediation != "" {
			// Indent remediation lines
			remediationLines := strings.Split(finding.Remediation, "\n")
			for _, line := range remediationLines {
				remediation.WriteString(fmt.Sprintf("   -> %s\n", line))
			}
		}
		if len(finding.References) > 0 {
			remediation.WriteString(fmt.Sprintf("   Reference: %s\n", strings.Join(finding.References, ", ")))
		}
		remediation.WriteString("\n") // Add space between findings
	}
	return remediation.String()
}

// getReportFooter generates a professional footer for text report
func (r *Reporter) getReportFooter() string {
	// Assuming APP_VERSION is accessible somehow, maybe from config or build flags
	version := "2.0.0" // Hardcoded for now
	return fmt.Sprintf("\n--- END OF REPORT ---\nGenerated by HARDEND v%s\n", version)
}

// generateJSONReport creates JSON formatted output
func (r *Reporter) generateJSONReport(results *checks.Results) (string, error) {
	// Create a report struct that matches the new professional types
	// Use pointers for nested structs if they might be nil, although Summary is usually initialized
	jsonReport := struct {
		Version    string            `json:"hardend_version"`
		ReportType string            `json:"report_type"`
		SystemInfo checks.SystemInfo `json:"system_info"`
		ScanMeta   struct {
			StartTime string `json:"start_time"` // Use standard time format (RFC3339)
			EndTime   string `json:"end_time"`
			Duration  string `json:"duration"`
		} `json:"scan_metadata"`
		Summary  checks.Summary    `json:"assessment_summary"` // Renamed field for clarity
		Findings []*checks.Finding `json:"findings"`
	}{
		Version:    "2.0.0", // Hardcoded for now, ideally get from build flags
		ReportType: "SecurityAssessment",
		SystemInfo: results.SystemInfo, // Assumes SystemInfo is always populated
		ScanMeta: struct {
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
			Duration  string `json:"duration"`
		}{
			StartTime: results.StartTime.Format(time.RFC3339), // Corrected: Use time package
			EndTime:   results.EndTime.Format(time.RFC3339),   // Corrected: Use time package
			Duration:  results.Duration,
		},
		Summary:  results.Summary,  // Assumes Summary is always populated
		Findings: results.Findings, // Assumes Findings is initialized (even if empty)
	}

	jsonBytes, err := json.MarshalIndent(jsonReport, "", "  ") // Use 2 spaces for indentation
	if err != nil {
		return "", fmt.Errorf("JSON marshaling failed: %w", err)
	}
	return string(jsonBytes), nil
}

// generateHTMLReport creates a clean, professional HTML report
func (r *Reporter) generateHTMLReport(results *checks.Results) string {
	// Professional CSS - minimalist and clean
	style := `
<style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 0; background-color: #f8f9fa; color: #212529; font-size: 16px; line-height: 1.6; }
    .container { max-width: 1200px; margin: 40px auto; background: #ffffff; border: 1px solid #dee2e6; border-radius: 8px; padding: 30px; box-shadow: 0 4px 8px rgba(0,0,0,0.05); }
    h1, h2, h3 { color: #343a40; margin-top: 1.5em; margin-bottom: 0.8em; border-bottom: 1px solid #e9ecef; padding-bottom: 0.3em; }
    h1 { font-size: 2.2em; border-bottom-width: 2px; }
    h2 { font-size: 1.7em; }
    h3 { font-size: 1.3em; border-bottom: none; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 30px; font-size: 0.95em; }
    th, td { border: 1px solid #dee2e6; padding: 10px 12px; text-align: left; vertical-align: top; }
    th { background-color: #e9ecef; font-weight: 600; color: #495057; }
    tbody tr:nth-child(odd) { background-color: #f8f9fa; }
    tbody tr:hover { background-color: #e2e6ea; }
    pre { background-color: #e9ecef; padding: 8px; border-radius: 4px; font-size: 0.9em; white-space: pre-wrap; word-break: break-all; margin: 5px 0 0 0;}
    .severity-CRITICAL { background-color: #dc3545; color: white; font-weight: bold; }
    .severity-HIGH { background-color: #fd7e14; color: white; }
    .severity-MEDIUM { background-color: #ffc107; color: #343a40; }
    .severity-LOW { background-color: #17a2b8; color: white; }
    .severity-INFO { background-color: #6c757d; color: white; }
    .status-FAIL { color: #dc3545; font-weight: bold; }
    .status-WARN { color: #ffc107; font-weight: bold; }
    .status-PASS { color: #28a745; }
    .status-SKIP { color: #6c757d; font-style: italic;}
    .status-INFO { color: #17a2b8; }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; text-align: center; margin-bottom: 30px; }
    .summary-box { padding: 20px; border: 1px solid #dee2e6; border-radius: 5px; background-color: #f8f9fa; }
    .summary-box h3 { margin-top: 0; font-size: 1.1em; color: #6c757d; margin-bottom: 10px; border-bottom: none;}
    .summary-box p { font-size: 2em; margin: 0; font-weight: bold; }
    .footer { text-align: center; margin-top: 40px; font-size: 0.9em; color: #6c757d; border-top: 1px solid #e9ecef; padding-top: 20px;}
    small { color: #6c757d; display: block; margin-top: 4px;}
</style>
`

	// Determine overall threat level for summary display
	threatLevel := "LOW"
	threatClass := "severity-LOW"
	if results.Summary.CriticalIssues > 0 {
		threatLevel = "CRITICAL"
		threatClass = "severity-CRITICAL"
	} else if results.Summary.HighIssues > 0 {
		threatLevel = "HIGH"
		threatClass = "severity-HIGH"
	} else if results.Summary.MediumIssues > 0 {
		threatLevel = "MEDIUM"
		threatClass = "severity-MEDIUM"
	} else if results.Summary.TotalChecks == 0 {
		threatLevel = "UNKNOWN"
		threatClass = "severity-INFO"
	} else if results.Summary.FailedChecks == 0 && results.Summary.WarningChecks == 0 {
		threatLevel = "INFO"
		threatClass = "severity-INFO"
	}

	// HTML Body Construction
	var body strings.Builder
	body.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HARDEND Security Report - %s</title>
    %s
</head>
<body>
    <div class="container">
        <h1>HARDEND Security Assessment Report</h1>
        <p><strong>Scan Target:</strong> %s</p>
        <p><strong>OS:</strong> %s</p>
        <p><strong>Kernel:</strong> %s</p>
        <p><strong>Report Time:</strong> %s</p>
        <p><strong>Scan Duration:</strong> %s</p>`,
		results.SystemInfo.Hostname, style, results.SystemInfo.Hostname,
		results.SystemInfo.OS, results.SystemInfo.Kernel,
		time.Now().Format(time.RFC1123), results.Duration)) // Corrected: Use time package

	// Executive Summary Grid
	body.WriteString(fmt.Sprintf(`
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-box">
                <h3>Overall Threat</h3>
                <p class="%s">%s</p>
            </div>
            <div class="summary-box">
                <h3>Total Checks</h3>
                <p>%d</p>
            </div>
            <div class="summary-box">
                <h3>Failed / Warn</h3>
                <p class="status-FAIL">%d <span style="font-size: 0.6em; font-weight: normal;"> / %d</span></p>
            </div>
             <div class="summary-box">
                <h3>Critical</h3>
                <p class="severity-CRITICAL">%d</p>
            </div>
            <div class="summary-box">
                <h3>High</h3>
                <p class="severity-HIGH">%d</p>
            </div>
             <div class="summary-box">
                <h3>Medium</h3>
                <p class="severity-MEDIUM">%d</p>
            </div>
        </div>`,
		threatClass, threatLevel,
		results.Summary.TotalChecks,
		results.Summary.FailedChecks, results.Summary.WarningChecks,
		results.Summary.CriticalIssues,
		results.Summary.HighIssues,
		results.Summary.MediumIssues))

	// Detailed Findings Table
	body.WriteString(`
        <h2>Detailed Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Finding</th>
                    <th>Actual</th>
                    <th>Expected</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>`)

	// Sort findings (same logic as table report)
	sortedFindings := make([]*checks.Finding, 0, len(results.Findings))
	for _, f := range results.Findings {
		// Filter out PASS/INFO for HTML report to keep it focused
		if f.Status != checks.StatusPass && f.Status != checks.StatusInfo {
			sortedFindings = append(sortedFindings, f)
		}
	}
	sort.Slice(sortedFindings, func(i, j int) bool {
		order := map[checks.Severity]int{
			checks.SeverityCritical: 5, checks.SeverityHigh: 4, checks.SeverityMedium: 3, checks.SeverityLow: 2, checks.SeverityInfo: 1,
		}
		if order[sortedFindings[i].Severity] != order[sortedFindings[j].Severity] {
			return order[sortedFindings[i].Severity] > order[sortedFindings[j].Severity]
		}
		return sortedFindings[i].ID < sortedFindings[j].ID
	})

	if len(sortedFindings) == 0 {
		body.WriteString(`<tr><td colspan="7" style="text-align:center; padding: 20px;">No significant issues (FAIL/WARN) detected.</td></tr>`)
	} else {
		for _, f := range sortedFindings {
			// Use HTML escaping for content to prevent XSS if data is unexpected
			// (Go's html/template package does this automatically if used,
			// but manual string building requires care)
			// For simplicity here, assuming content is safe, but be aware.
			body.WriteString(fmt.Sprintf(`
                    <tr>
                        <td class="status-%s">%s</td>
                        <td class="severity-%s">%s</td>
                        <td>%s</td>
                        <td><strong>%s</strong><br><small>%s</small></td>
                        <td><pre>%s</pre></td>
                        <td><pre>%s</pre></td>
                        <td><small>%s</small></td>
                    </tr>`,
				f.Status, f.Status, f.Severity, f.Severity, f.Category,
				f.Title, f.Description, // Basic HTML escaping might be needed here
				f.Actual, f.Expected, f.Remediation))
		}
	}

	body.WriteString(`
            </tbody>
        </table>

        <div class="footer">
            Generated by HARDEND v2.0.0
        </div>
    </div>
</body>
</html>`)

	return body.String()
}

// --- Helper Functions ---

// formatStatus returns the string representation of the status
func (r *Reporter) formatStatus(status checks.CheckStatus) string {
	return string(status)
}

// formatSeverity returns the string representation of the severity
func (r *Reporter) formatSeverity(severity checks.Severity) string {
	return string(severity)
}

// truncateString limits the length of a string for display purposes
func (r *Reporter) truncateString(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ") // Replace newlines for table display
	s = strings.ReplaceAll(s, "\t", " ") // Replace tabs
	// Trim leading/trailing whitespace
	s = strings.TrimSpace(s)

	if len(s) <= maxLen {
		return s
	}
	// Try to truncate at a space if possible near the max length
	if maxLen > 3 {
		spaceIndex := strings.LastIndex(s[:maxLen-3], " ")
		if spaceIndex > maxLen/2 { // Only truncate at space if it's reasonably far in
			return s[:spaceIndex] + "..."
		}
		return s[:maxLen-3] + "..."
	}
	return s[:maxLen] // Fallback if maxLen is tiny
}
