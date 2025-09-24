package tests

import (
	checks "github.com/ConstantineCTF/hardend/pkg/checks"
	"testing"

	checks "github.com/ConstantineCTF/hardend/pkg/checks"
)

// TestTypesBasic tests basic type functionality
func TestTypesBasic(t *testing.T) {
<<<<<<< Updated upstream
=======
	// Test severity levels
>>>>>>> Stashed changes
	severities := []checks.Severity{
		checks.SeverityInfo,
		checks.SeverityLow,
		checks.SeverityMedium,
		checks.SeverityHigh,
		checks.SeverityCritical,
	}

	if len(severities) != 5 {
		t.Errorf("Expected 5 severity levels, got %d", len(severities))
	}

<<<<<<< Updated upstream
=======
	// Test check status
>>>>>>> Stashed changes
	statuses := []checks.CheckStatus{
		checks.StatusPass,
		checks.StatusFail,
		checks.StatusWarn,
		checks.StatusInfo,
		checks.StatusSkip,
	}

	if len(statuses) != 5 {
		t.Errorf("Expected 5 check statuses, got %d", len(statuses))
	}
}

// TestResultsBasic tests basic Results functionality
func TestResultsBasic(t *testing.T) {
	results := &checks.Results{
		SystemInfo: checks.SystemInfo{
			Hostname: "test-host",
			OS:       "Linux",
		},
		Findings: make([]*checks.Finding, 0),
		Summary:  checks.Summary{},
	}

<<<<<<< Updated upstream
=======
	// Test adding a finding
>>>>>>> Stashed changes
	finding := &checks.Finding{
		ID:          "TEST_001",
		Title:       "Test Finding",
		Description: "Test finding description",
		Severity:    checks.SeverityMedium,
		Status:      checks.StatusFail,
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
	results := &checks.Results{
		Summary: checks.Summary{},
	}

	threatLevel := results.GetThreatLevel()
	if threatLevel != "MINIMAL" {
		t.Errorf("Expected MINIMAL threat level, got %s", threatLevel)
	}

	results.Summary.CriticalIssues = 1
	threatLevel = results.GetThreatLevel()
	if threatLevel != "CRITICAL" {
		t.Errorf("Expected CRITICAL threat level, got %s", threatLevel)
	}
}

// TestSecurityScore tests security score calculation
func TestSecurityScore(t *testing.T) {
	results := &checks.Results{
		Summary: checks.Summary{
			TotalChecks:  10,
			PassedChecks: 8,
			FailedChecks: 2,
		},
	}

	score := results.GenerateSecurityScore()

	expectedScore := 80.0
	if score != expectedScore {
		t.Errorf("Expected security score %.1f, got %.1f", expectedScore, score)
	}
}

// TestFindingString tests Finding string representation
func TestFindingString(t *testing.T) {
	finding := &checks.Finding{
		ID:          "TEST_001",
		Title:       "Test Finding",
		Severity:    checks.SeverityHigh,
		Status:      checks.StatusFail,
		Exploitable: true,
	}

	result := finding.String()
	expected := "[FAIL] HIGH: Test Finding (TEST_001) [EXPLOITABLE]"

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}
