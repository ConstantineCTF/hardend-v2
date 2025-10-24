package checks

import (
	"fmt"
	"time"
)

// Severity levels for security findings
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// CheckStatus represents the result of a security check
type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusFail CheckStatus = "FAIL"
	StatusWarn CheckStatus = "WARN"
	StatusInfo CheckStatus = "INFO"
	StatusSkip CheckStatus = "SKIP"
)

// Finding represents a single security finding
type Finding struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	Status      CheckStatus `json:"status"`
	Expected    string      `json:"expected"`
	Actual      string      `json:"actual"`
	Remediation string      `json:"remediation"`
	References  []string    `json:"references,omitempty"`
	CVEIDs      []string    `json:"cve_ids,omitempty"`
	Category    string      `json:"category"`
	Timestamp   time.Time   `json:"timestamp"`
	Exploitable bool        `json:"exploitable"`
}

// Results holds all security assessment results
type Results struct {
	SystemInfo SystemInfo `json:"system_info"`
	Findings   []*Finding `json:"findings"`
	Summary    Summary    `json:"summary"`
	StartTime  time.Time  `json:"start_time"`
	EndTime    time.Time  `json:"end_time"`
	Duration   string     `json:"duration"`
}

// SystemInfo contains enhanced system information
type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	Uptime       string `json:"uptime"`
	LoadAverage  string `json:"load_average"`
	CPUCores     int    `json:"cpu_cores"`
	MemoryInfo   string `json:"memory_info"`
}

// Summary provides an overview of check results
type Summary struct {
	TotalChecks    int `json:"total_checks"`
	PassedChecks   int `json:"passed_checks"`
	FailedChecks   int `json:"failed_checks"`
	WarningChecks  int `json:"warning_checks"`
	SkippedChecks  int `json:"skipped_checks"`
	CriticalIssues int `json:"critical_issues"`
	HighIssues     int `json:"high_issues"`
	MediumIssues   int `json:"medium_issues"`
	LowIssues      int `json:"low_issues"`
}

// HasCriticalVulnerabilities returns true if there are critical security vulnerabilities
func (r *Results) HasCriticalVulnerabilities() bool {
	return r.Summary.CriticalIssues > 0
}

// AddFinding adds a finding to the results and updates the summary
func (r *Results) AddFinding(finding *Finding) {
	finding.Timestamp = time.Now()
	r.Findings = append(r.Findings, finding)

	// Update summary
	r.Summary.TotalChecks++
	switch finding.Status {
	case StatusPass:
		r.Summary.PassedChecks++
	case StatusFail:
		r.Summary.FailedChecks++
	case StatusWarn:
		r.Summary.WarningChecks++
	case StatusSkip:
		r.Summary.SkippedChecks++
	}

	switch finding.Severity {
	case SeverityCritical:
		r.Summary.CriticalIssues++
	case SeverityHigh:
		r.Summary.HighIssues++
	case SeverityMedium:
		r.Summary.MediumIssues++
	case SeverityLow:
		r.Summary.LowIssues++
	}
}

// String returns a simple string representation of the finding
func (f *Finding) String() string {
	exploitFlag := ""
	if f.Exploitable {
		exploitFlag = " [EXPLOITABLE]"
	}
	return fmt.Sprintf("[%s] %s: %s (%s)%s", f.Status, f.Severity, f.Title, f.ID, exploitFlag)
}

// GetSummaryString returns a simple summary string
func (r *Results) GetSummaryString() string {
	return fmt.Sprintf(
		"Assessment Summary: Total Checks: %d, Passed: %d, Failed: %d, Critical: %d, High: %d",
		r.Summary.TotalChecks, r.Summary.PassedChecks, r.Summary.FailedChecks,
		r.Summary.CriticalIssues, r.Summary.HighIssues,
	)
}
