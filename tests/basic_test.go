package checks

import (
	"testing"
)

// TestTypesBasic tests basic type functionality
func TestTypesBasic(t *testing.T) {
	// Test severity levels
	severities := []Severity{
		SeverityInfo,
		SeverityLow,
		SeverityMedium,
		SeverityHigh,
		SeverityCritical,
	}

	if len(severities) != 5 {
		t.Errorf("Expected 5 severity levels, got %d", len(severities))
	}

	// Test check status
	statuses := []CheckStatus{
		StatusPass,
		StatusFail,
		StatusWarn,
		StatusInfo,
		StatusSkip,
	}

	if len(statuses) != 5 {
		t.Errorf("Expected 5 check statuses, got %d", len(statuses))
	}
}

// TestResultsBasic tests basic Results functionality
func TestResultsBasic(t *testing.T) {
	results := &Results{
		SystemInfo: SystemInfo{
			Hostname: "test-host",
			OS:       "Linux",
		},
		Findings: make([]*Finding, 0),
		Summary:  Summary{},
	}

	// Test adding a finding
	finding := &Finding{
		ID:          "TEST_001",
		Title:       "Test Finding",
		Description: "Test finding description",
		Severity:    SeverityMedium,
		Status:      StatusFail,
		Expected:    "secure configuration",
		Actual:      "insecure configuration",
		Category:    "Test Category",
		Exploitable: true,
	}

	results.AddFinding(finding)

	if len(results.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(results.Findings))
	}

	if results.Summary.TotalChecks != 1 {
		t.Errorf("Expected 1 total check, got %d", results.Summary.TotalChecks)
	}

	if results.Summary.FailedChecks != 1 {
		t.Errorf("Expected 1 failed check, got %d", results.Summary.FailedChecks)
	}

	if results.Summary.MediumIssues != 1 {
		t.Errorf("Expected 1 medium issue, got %d", results.Summary.MediumIssues)
	}
}

// TestThreatLevel tests threat level calculation
func TestThreatLevel(t *testing.T) {
	results := &Results{
		Summary: Summary{},
	}

	// Test minimal threat level
	threatLevel := results.GetThreatLevel()
	if threatLevel != "MINIMAL" {
		t.Errorf("Expected MINIMAL threat level, got %s", threatLevel)
	}

	// Test critical threat level
	results.Summary.CriticalIssues = 1
	threatLevel = results.GetThreatLevel()
	if threatLevel != "CRITICAL" {
		t.Errorf("Expected CRITICAL threat level, got %s", threatLevel)
	}
}

// TestSecurityScore tests security score calculation
func TestSecurityScore(t *testing.T) {
	results := &Results{
		Summary: Summary{
			TotalChecks:  10,
			PassedChecks: 8,
			FailedChecks: 2,
		},
	}

	score := results.GenerateSecurityScore()

	// Should be 80% (8/10 * 100)
	expectedScore := 80.0
	if score != expectedScore {
		t.Errorf("Expected security score %.1f, got %.1f", expectedScore, score)
	}
}

// TestFindingString tests Finding string representation
func TestFindingString(t *testing.T) {
	finding := &Finding{
		ID:          "TEST_001",
		Title:       "Test Finding",
		Severity:    SeverityHigh,
		Status:      StatusFail,
		Exploitable: true,
	}

	result := finding.String()
	expected := "[FAIL] HIGH: Test Finding (TEST_001) [EXPLOITABLE]"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}
