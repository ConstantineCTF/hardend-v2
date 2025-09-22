package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ConstantineCTF/hardend/pkg/checks"
	"github.com/ConstantineCTF/hardend/pkg/utils"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// CyberpunkReporter generates cyberpunk-themed security reports
type CyberpunkReporter struct {
	format string
	quiet  bool
}

// NewCyberpunkReporter creates a new cyberpunk-themed reporter
func NewCyberpunkReporter(format string, quiet bool) *CyberpunkReporter {
	return &CyberpunkReporter{
		format: format,
		quiet:  quiet,
	}
}

// Generate creates a cyberpunk-styled security report
func (cr *CyberpunkReporter) Generate(results *checks.Results, outputFile string) error {
	var output string
	var err error

	switch cr.format {
	case "cyberpunk", "table":
		output = cr.generateCyberpunkTable(results)
	case "matrix":
		output = cr.generateMatrixReport(results)
	case "json":
		output, err = cr.generateJSONReport(results)
		if err != nil {
			return err
		}
	case "html":
		output = cr.generateHTMLReport(results)
	default:
		output = cr.generateCyberpunkTable(results)
	}

	if outputFile != "" {
		return os.WriteFile(outputFile, []byte(output), 0644)
	}

	fmt.Print(output)
	return nil
}

// generateCyberpunkTable creates a cyberpunk-styled table report
func (cr *CyberpunkReporter) generateCyberpunkTable(results *checks.Results) string {
	var report strings.Builder

	// Header with cyberpunk styling
	report.WriteString(cr.getCyberpunkHeader(results))

	// System information
	report.WriteString(cr.getSystemInfoSection(results))

	// Executive summary
	report.WriteString(cr.getExecutiveSummary(results))

	// Findings table
	report.WriteString(cr.getCyberpunkTable(results))

	// Summary statistics
	report.WriteString(cr.getSummarySection(results))

	// Remediation guide
	report.WriteString(cr.getRemediationSection(results))

	// Footer
	report.WriteString(cr.getCyberpunkFooter())

	return report.String()
}

// getCyberpunkHeader generates the cyberpunk-styled header
func (cr *CyberpunkReporter) getCyberpunkHeader(results *checks.Results) string {
	header := `
    ╔════════════════════════════════════════════════════════════════════════╗
    ║                    ◢◤ HARDEND SECURITY ASSESSMENT ◢◤                    ║
    ║                          Neural Threat Analysis                        ║
    ╚════════════════════════════════════════════════════════════════════════╝

    ◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤
    ▓▓▓ THREAT ASSESSMENT COMPLETE - NEURAL INTERFACE ACTIVE ▓▓▓
    ◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤

`
	if !cr.quiet {
		return color.New(color.FgCyan, color.Bold).Sprint(header)
	}
	return header
}

// getSystemInfoSection generates system information display
func (cr *CyberpunkReporter) getSystemInfoSection(results *checks.Results) string {
	var section strings.Builder

	section.WriteString("    ╔══════════════════════════════════════════════════════════════╗\n")
	section.WriteString("    ║                     SYSTEM MATRIX INFO                       ║\n")
	section.WriteString("    ╚══════════════════════════════════════════════════════════════╝\n")
	section.WriteString(fmt.Sprintf("    ◢◤ Target System: %s\n", results.SystemInfo.Hostname))
	section.WriteString(fmt.Sprintf("    ◢◤ Neural OS: %s (%s)\n", results.SystemInfo.OS, results.SystemInfo.Architecture))
	section.WriteString(fmt.Sprintf("    ◢◤ Kernel Version: %s\n", results.SystemInfo.Kernel))
	section.WriteString(fmt.Sprintf("    ◢◤ System Uptime: %s\n", results.SystemInfo.Uptime))
	section.WriteString(fmt.Sprintf("    ◢◤ Scan Started: %s\n", results.StartTime.Format("2006-01-02 15:04:05")))
	section.WriteString(fmt.Sprintf("    ◢◤ Scan Duration: %s\n", results.Duration))
	section.WriteString("\n")

	if !cr.quiet {
		return color.New(color.FgCyan).Sprint(section.String())
	}
	return section.String()
}

// getExecutiveSummary generates executive summary
func (cr *CyberpunkReporter) getExecutiveSummary(results *checks.Results) string {
	var summary strings.Builder

	summary.WriteString("    ╔══════════════════════════════════════════════════════════════╗\n")
	summary.WriteString("    ║                   EXECUTIVE THREAT SUMMARY                   ║\n")
	summary.WriteString("    ╚══════════════════════════════════════════════════════════════╝\n")

	// Threat level assessment
	threatLevel := "LOW"
	threatColor := color.FgGreen

	if results.Summary.CriticalIssues > 0 {
		threatLevel = "CRITICAL"
		threatColor = color.FgRed
	} else if results.Summary.HighIssues > 5 {
		threatLevel = "HIGH"
		threatColor = color.FgRed
	} else if results.Summary.HighIssues > 0 || results.Summary.MediumIssues > 10 {
		threatLevel = "MEDIUM"
		threatColor = color.FgYellow
	}

	if !cr.quiet {
		summary.WriteString(color.New(color.Bold, threatColor).Sprintf("    ◢◤ THREAT LEVEL: %s\n", threatLevel))

		if results.Summary.CriticalIssues > 0 {
			summary.WriteString(color.New(color.FgRed, color.Bold).Sprintf("    ◢◤ CRITICAL VULNERABILITIES: %d [IMMEDIATE ACTION REQUIRED]\n", results.Summary.CriticalIssues))
		}
		if results.Summary.HighIssues > 0 {
			summary.WriteString(color.New(color.FgRed).Sprintf("    ◢◤ High Priority Issues: %d\n", results.Summary.HighIssues))
		}
		if results.Summary.MediumIssues > 0 {
			summary.WriteString(color.New(color.FgYellow).Sprintf("    ◢◤ Medium Priority Issues: %d\n", results.Summary.MediumIssues))
		}
	} else {
		summary.WriteString(fmt.Sprintf("    ◢◤ THREAT LEVEL: %s\n", threatLevel))
		summary.WriteString(fmt.Sprintf("    ◢◤ Critical: %d, High: %d, Medium: %d, Low: %d\n",
			results.Summary.CriticalIssues, results.Summary.HighIssues,
			results.Summary.MediumIssues, results.Summary.LowIssues))
	}

	summary.WriteString("\n")
	return summary.String()
}

// getCyberpunkTable generates the main findings table
func (cr *CyberpunkReporter) getCyberpunkTable(results *checks.Results) string {
	var tableOutput strings.Builder

	tableOutput.WriteString("    ╔══════════════════════════════════════════════════════════════╗\n")
	tableOutput.WriteString("    ║                    VULNERABILITY MATRIX                      ║\n")
	tableOutput.WriteString("    ╚══════════════════════════════════════════════════════════════╝\n\n")

	// Sort findings by severity
	sortedFindings := make([]*checks.Finding, len(results.Findings))
	copy(sortedFindings, results.Findings)
	sort.Slice(sortedFindings, func(i, j int) bool {
		severityOrder := map[checks.Severity]int{
			checks.SeverityCritical: 4,
			checks.SeverityHigh:     3,
			checks.SeverityMedium:   2,
			checks.SeverityLow:      1,
			checks.SeverityInfo:     0,
		}
		return severityOrder[sortedFindings[i].Severity] > severityOrder[sortedFindings[j].Severity]
	})

	// Group findings by category
	categories := make(map[string][]*checks.Finding)
	for _, finding := range sortedFindings {
		if finding.Status == checks.StatusPass && cr.format != "matrix" {
			continue // Skip passed checks in normal mode
		}
		categories[finding.Category] = append(categories[finding.Category], finding)
	}

	// Generate tables for each category
	for category, findings := range categories {
		if len(findings) == 0 {
			continue
		}

		tableOutput.WriteString(fmt.Sprintf("\n    ◢◤ %s ANALYSIS:\n", strings.ToUpper(category)))
		tableOutput.WriteString("    " + strings.Repeat("─", 70) + "\n")

		table := tablewriter.NewWriter(&tableOutput)
		table.SetHeader([]string{"STATUS", "SEVERITY", "FINDING", "CURRENT", "EXPECTED"})
		table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
		table.SetCenterSeparator("|")
		table.SetColumnSeparator("|")
		table.SetRowSeparator("-")
		table.SetHeaderAlignment(tablewriter.ALIGN_CENTER)
		table.SetAlignment(tablewriter.ALIGN_LEFT)
		table.SetTablePadding("  ")

		for _, finding := range findings {
			status := cr.formatStatus(finding.Status)
			severity := cr.formatSeverity(finding.Severity)
			title := cr.truncateString(finding.Title, 30)
			actual := cr.truncateString(finding.Actual, 15)
			expected := cr.truncateString(finding.Expected, 15)

			table.Append([]string{status, severity, title, actual, expected})
		}

		table.Render()
	}

	return tableOutput.String()
}

// getSummarySection generates the summary statistics section
func (cr *CyberpunkReporter) getSummarySection(results *checks.Results) string {
	var summary strings.Builder

	summary.WriteString("\n    ╔══════════════════════════════════════════════════════════════╗\n")
	summary.WriteString("    ║                     NEURAL SUMMARY MATRIX                    ║\n")
	summary.WriteString("    ╚══════════════════════════════════════════════════════════════╝\n")

	total := results.Summary.TotalChecks
	passed := results.Summary.PassedChecks
	failed := results.Summary.FailedChecks

	passRate := float64(passed) / float64(total) * 100

	if !cr.quiet {
		summary.WriteString(color.New(color.FgCyan).Sprintf("    ◢◤ Total Security Checks: %d\n", total))
		summary.WriteString(color.New(color.FgGreen).Sprintf("    ◢◤ Passed: %d (%.1f%%)\n", passed, passRate))
		summary.WriteString(color.New(color.FgRed).Sprintf("    ◢◤ Failed: %d (%.1f%%)\n", failed, float64(failed)/float64(total)*100))
		summary.WriteString(color.New(color.FgYellow).Sprintf("    ◢◤ Warnings: %d\n", results.Summary.WarningChecks))
		summary.WriteString(color.New(color.FgMagenta).Sprintf("    ◢◤ Skipped: %d\n", results.Summary.SkippedChecks))
	} else {
		summary.WriteString(fmt.Sprintf("    ◢◤ Total: %d, Passed: %d (%.1f%%), Failed: %d\n",
			total, passed, passRate, failed))
	}

	summary.WriteString("\n")

	// Security score calculation
	maxScore := float64(total * 100)
	currentScore := float64(passed*100 + results.Summary.WarningChecks*50)
	securityScore := currentScore / maxScore * 100

	scoreColor := color.FgRed
	if securityScore >= 90 {
		scoreColor = color.FgGreen
	} else if securityScore >= 70 {
		scoreColor = color.FgYellow
	}

	if !cr.quiet {
		summary.WriteString(color.New(color.Bold, scoreColor).Sprintf("    ◢◤ SECURITY SCORE: %.1f/100\n", securityScore))
	} else {
		summary.WriteString(fmt.Sprintf("    ◢◤ SECURITY SCORE: %.1f/100\n", securityScore))
	}

	return summary.String()
}

// getRemediationSection generates remediation guidance
func (cr *CyberpunkReporter) getRemediationSection(results *checks.Results) string {
	var remediation strings.Builder

	remediation.WriteString("\n    ╔══════════════════════════════════════════════════════════════╗\n")
	remediation.WriteString("    ║                   PRIORITY REMEDIATION GUIDE                 ║\n")
	remediation.WriteString("    ╚══════════════════════════════════════════════════════════════╝\n\n")

	// Get critical and high severity failures
	criticalFindings := []*checks.Finding{}
	highFindings := []*checks.Finding{}

	for _, finding := range results.Findings {
		if finding.Status == checks.StatusFail {
			switch finding.Severity {
			case checks.SeverityCritical:
				criticalFindings = append(criticalFindings, finding)
			case checks.SeverityHigh:
				if len(highFindings) < 5 { // Limit to top 5
					highFindings = append(highFindings, finding)
				}
			}
		}
	}

	// Show critical remediations
	if len(criticalFindings) > 0 {
		remediation.WriteString("    ◢◤ CRITICAL ISSUES (Immediate Action Required):\n\n")
		for i, finding := range criticalFindings {
			remediation.WriteString(fmt.Sprintf("    %d. %s\n", i+1, finding.Title))
			remediation.WriteString(fmt.Sprintf("       %s\n\n", finding.Remediation))
		}
	}

	// Show high priority remediations
	if len(highFindings) > 0 {
		remediation.WriteString("    ◢◤ HIGH PRIORITY ISSUES:\n\n")
		for i, finding := range highFindings {
			remediation.WriteString(fmt.Sprintf("    %d. %s\n", i+1, finding.Title))
			remediation.WriteString(fmt.Sprintf("       %s\n\n", finding.Remediation))
		}
	}

	return remediation.String()
}

// getCyberpunkFooter generates the cyberpunk-styled footer
func (cr *CyberpunkReporter) getCyberpunkFooter() string {
	footer := `
    ◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤
    ▓▓▓ "Wake the f*ck up, samurai. We have a city to burn." ▓▓▓
    ▓▓▓ HARDEND v2077.1.0 - Neural Security Assessment ▓▓▓
    ◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤

`
	if !cr.quiet {
		return color.New(color.FgMagenta, color.Bold).Sprint(footer)
	}
	return footer
}

// generateMatrixReport creates matrix-style output
func (cr *CyberpunkReporter) generateMatrixReport(results *checks.Results) string {
	var matrix strings.Builder

	matrix.WriteString("\n")
	if !cr.quiet {
		utils.MatrixEffect(2 * time.Second)
	}

	matrix.WriteString(color.New(color.FgGreen, color.Bold).Sprint("    ◢◤ ENTERING THE SECURITY MATRIX...\n\n"))

	// Matrix-style findings display
	for _, finding := range results.Findings {
		status := "●"
		statusColor := color.FgGreen

		switch finding.Status {
		case checks.StatusFail:
			status = "◉"
			statusColor = color.FgRed
		case checks.StatusWarn:
			status = "◐"
			statusColor = color.FgYellow
		case checks.StatusSkip:
			status = "○"
			statusColor = color.FgMagenta
		}

		if !cr.quiet {
			matrix.WriteString(color.New(statusColor).Sprintf("%s ", status))
			matrix.WriteString(color.New(color.FgGreen).Sprintf("%s\n", finding.Title))
		} else {
			matrix.WriteString(fmt.Sprintf("%s %s\n", status, finding.Title))
		}
	}

	matrix.WriteString("\n")
	matrix.WriteString(color.New(color.FgCyan, color.Bold).Sprint("    ◢◤ MATRIX CONNECTION TERMINATED\n"))

	return matrix.String()
}

// generateJSONReport creates JSON formatted output
func (cr *CyberpunkReporter) generateJSONReport(results *checks.Results) (string, error) {
	// Add cyberpunk metadata to JSON
	jsonReport := map[string]interface{}{
		"hardend_version":  "2077.1.0",
		"report_type":      "cyberpunk_security_assessment",
		"neural_interface": true,
		"matrix_analysis":  true,
		"system_info":      results.SystemInfo,
		"scan_metadata": map[string]interface{}{
			"start_time": results.StartTime,
			"end_time":   results.EndTime,
			"duration":   results.Duration,
		},
		"threat_assessment": results.Summary,
		"vulnerabilities":   results.Findings,
	}

	jsonBytes, err := json.MarshalIndent(jsonReport, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}

// generateHTMLReport creates HTML formatted output
func (cr *CyberpunkReporter) generateHTMLReport(results *checks.Results) string {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HARDEND Security Assessment - %s</title>
    <style>
        body {
            background: #0a0a0a;
            color: #00ff41;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 20px;
        }
        .header {
            text-align: center;
            border: 2px solid #00ff41;
            padding: 20px;
            margin-bottom: 30px;
            background: linear-gradient(45deg, #001a0a, #000a05);
        }
        .section {
            border: 1px solid #00aa33;
            margin: 20px 0;
            padding: 15px;
            background: #050505;
        }
        .critical { color: #ff0040; }
        .high { color: #ff8800; }
        .medium { color: #ffaa00; }
        .low { color: #00aa88; }
        .info { color: #0088ff; }
        .pass { color: #00ff41; }
        .fail { color: #ff0040; }
        .warn { color: #ffaa00; }
        table {
            width: 100%%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            border: 1px solid #00aa33;
            padding: 8px;
            text-align: left;
        }
        th {
            background: #002200;
            color: #00ff41;
        }
        .matrix-text {
            text-shadow: 0 0 10px #00ff41;
        }
    </style>
</head>
<body>
    <div class="header matrix-text">
        <h1>◢◤ HARDEND SECURITY ASSESSMENT ◢◤</h1>
        <h2>Neural Threat Analysis Report</h2>
        <p>Target: %s | Kernel: %s</p>
        <p>Scan Duration: %s</p>
    </div>`, results.SystemInfo.Hostname, results.SystemInfo.Hostname,
		results.SystemInfo.Kernel, results.Duration)

	// Add findings table
	html += `<div class="section">
        <h3>◢◤ VULNERABILITY MATRIX</h3>
        <table>
            <tr>
                <th>Status</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Finding</th>
                <th>Expected</th>
                <th>Actual</th>
            </tr>`

	for _, finding := range results.Findings {
		statusClass := string(finding.Status)
		severityClass := strings.ToLower(string(finding.Severity))

		html += fmt.Sprintf(`
            <tr>
                <td class="%s">%s</td>
                <td class="%s">%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
            </tr>`, statusClass, finding.Status, severityClass, finding.Severity,
			finding.Category, finding.Title, finding.Expected, finding.Actual)
	}

	html += `</table></div>

    <div class="section">
        <h3>◢◤ NEURAL SUMMARY MATRIX</h3>
        <p>Total Checks: ` + fmt.Sprintf("%d", results.Summary.TotalChecks) + `</p>
        <p class="pass">Passed: ` + fmt.Sprintf("%d", results.Summary.PassedChecks) + `</p>
        <p class="fail">Failed: ` + fmt.Sprintf("%d", results.Summary.FailedChecks) + `</p>
        <p class="critical">Critical Issues: ` + fmt.Sprintf("%d", results.Summary.CriticalIssues) + `</p>
        <p class="high">High Issues: ` + fmt.Sprintf("%d", results.Summary.HighIssues) + `</p>
    </div>

    <div class="header matrix-text">
        <p>"Wake the f*ck up, samurai. We have a city to burn."</p>
        <p>HARDEND v2077.1.0 - Neural Security Assessment</p>
    </div>
</body>
</html>`

	return html
}

// Helper functions

func (cr *CyberpunkReporter) formatStatus(status checks.CheckStatus) string {
	if cr.quiet {
		return string(status)
	}

	switch status {
	case checks.StatusPass:
		return color.New(color.FgGreen, color.Bold).Sprint("✓ PASS")
	case checks.StatusFail:
		return color.New(color.FgRed, color.Bold).Sprint("✗ FAIL")
	case checks.StatusWarn:
		return color.New(color.FgYellow, color.Bold).Sprint("⚠ WARN")
	case checks.StatusSkip:
		return color.New(color.FgMagenta).Sprint("⊘ SKIP")
	default:
		return color.New(color.FgCyan).Sprint("? INFO")
	}
}

func (cr *CyberpunkReporter) formatSeverity(severity checks.Severity) string {
	if cr.quiet {
		return string(severity)
	}

	switch severity {
	case checks.SeverityCritical:
		return color.New(color.FgRed, color.Bold, color.BlinkSlow).Sprint("CRITICAL")
	case checks.SeverityHigh:
		return color.New(color.FgRed, color.Bold).Sprint("HIGH")
	case checks.SeverityMedium:
		return color.New(color.FgYellow, color.Bold).Sprint("MEDIUM")
	case checks.SeverityLow:
		return color.New(color.FgGreen).Sprint("LOW")
	default:
		return color.New(color.FgCyan).Sprint("INFO")
	}
}

func (cr *CyberpunkReporter) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
