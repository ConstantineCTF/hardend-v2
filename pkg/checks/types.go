package checks

import (
	"fmt"
	"time"
)

// Severity levels for cyberpunk security findings
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// CheckStatus represents the result of a cyberpunk security check
type CheckStatus string

const (
	StatusPass CheckStatus = "PASS"
	StatusFail CheckStatus = "FAIL"
	StatusWarn CheckStatus = "WARN"
	StatusInfo CheckStatus = "INFO"
	StatusSkip CheckStatus = "SKIP"
)

// Finding represents a cyberpunk-enhanced security finding
type Finding struct {
	ID           string      `json:"id"`
	Title        string      `json:"title"`
	Description  string      `json:"description"`
	Severity     Severity    `json:"severity"`
	Status       CheckStatus `json:"status"`
	Expected     string      `json:"expected"`
	Actual       string      `json:"actual"`
	Remediation  string      `json:"remediation"`
	References   []string    `json:"references,omitempty"`
	CVEIDs       []string    `json:"cve_ids,omitempty"`
	Category     string      `json:"category"`
	Timestamp    time.Time   `json:"timestamp"`
	Exploitable  bool        `json:"exploitable"`
	ThreatLevel  string      `json:"threat_level,omitempty"`
	AttackVector string      `json:"attack_vector,omitempty"`
	// Cyberpunk enhancements
	NeuralThreat    bool    `json:"neural_threat"`
	ICEBypass       bool    `json:"ice_bypass"`
	GhostAccess     bool    `json:"ghost_access"`
	MatrixAnomaly   bool    `json:"matrix_anomaly"`
	ThreatScore     float64 `json:"threat_score"`
	DetectionMethod string  `json:"detection_method,omitempty"`
}

// Results holds all cyberpunk security assessment results
type Results struct {
	SystemInfo SystemInfo `json:"system_info"`
	Findings   []*Finding `json:"findings"`
	Summary    Summary    `json:"summary"`
	StartTime  time.Time  `json:"start_time"`
	EndTime    time.Time  `json:"end_time"`
	Duration   string     `json:"duration"`
	// Cyberpunk enhancements
	NeuralInterface   bool           `json:"neural_interface"`
	GhostModeActive   bool           `json:"ghost_mode_active"`
	StealthModeActive bool           `json:"stealth_mode_active"`
	ThreatAssessment  ThreatLevel    `json:"threat_assessment"`
	SecurityScore     float64        `json:"security_score"`
	AttackVectors     []AttackVector `json:"attack_vectors,omitempty"`
	RemediationPlan   []Remediation  `json:"remediation_plan,omitempty"`
}

// SystemInfo contains enhanced cyberpunk system information
type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	Uptime       string `json:"uptime"`
	LoadAverage  string `json:"load_average"`
	CPUCores     int    `json:"cpu_cores"`
	MemoryInfo   string `json:"memory_info"`
	// Cyberpunk enhancements
	NeuralCores       int      `json:"neural_cores"`
	ICELevel          int      `json:"ice_level"`
	SecurityRating    string   `json:"security_rating"`
	ThreatIndicators  []string `json:"threat_indicators,omitempty"`
	SystemFingerprint string   `json:"system_fingerprint"`
}

// Summary provides cyberpunk-enhanced overview of check results
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
	// Cyberpunk enhancements
	ExploitableVulns   int     `json:"exploitable_vulnerabilities"`
	NeuralThreats      int     `json:"neural_threats"`
	ICEBypasses        int     `json:"ice_bypasses"`
	GhostAccesses      int     `json:"ghost_accesses"`
	MatrixAnomalies    int     `json:"matrix_anomalies"`
	OverallThreatScore float64 `json:"overall_threat_score"`
}

// ThreatLevel represents cyberpunk threat assessment
type ThreatLevel struct {
	Level       string    `json:"level"`
	Score       float64   `json:"score"`
	Description string    `json:"description"`
	Indicators  []string  `json:"indicators"`
	Assessment  time.Time `json:"assessment_time"`
}

// AttackVector represents potential attack methods
type AttackVector struct {
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	Severity       Severity `json:"severity"`
	Description    string   `json:"description"`
	Exploitability string   `json:"exploitability"`
	Impact         string   `json:"impact"`
	Mitigation     string   `json:"mitigation"`
	CVEIDs         []string `json:"cve_ids,omitempty"`
}

// Remediation represents cyberpunk-style remediation guidance
type Remediation struct {
	Priority     int      `json:"priority"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Commands     []string `json:"commands"`
	References   []string `json:"references"`
	Difficulty   string   `json:"difficulty"`
	TimeRequired string   `json:"time_required"`
	RiskLevel    string   `json:"risk_level"`
}

// NeuralPathway represents kernel parameter security
type NeuralPathway struct {
	Parameter     string `json:"parameter"`
	CurrentValue  string `json:"current_value"`
	ExpectedValue string `json:"expected_value"`
	Secure        bool   `json:"secure"`
	ThreatLevel   string `json:"threat_level"`
	Exploitable   bool   `json:"exploitable"`
}

// ICEBarrier represents service security state
type ICEBarrier struct {
	ServiceName  string `json:"service_name"`
	Running      bool   `json:"running"`
	Enabled      bool   `json:"enabled"`
	ShouldRun    bool   `json:"should_run"`
	ThreatLevel  string `json:"threat_level"`
	Exploitable  bool   `json:"exploitable"`
	AttackVector string `json:"attack_vector"`
}

// GhostProtocol represents SSH security configuration
type GhostProtocol struct {
	Parameter   string `json:"parameter"`
	Value       string `json:"value"`
	Secure      bool   `json:"secure"`
	ThreatLevel string `json:"threat_level"`
	Exploitable bool   `json:"exploitable"`
}

// MatrixNode represents filesystem security element
type MatrixNode struct {
	Path        string   `json:"path"`
	Type        string   `json:"type"`
	Permissions string   `json:"permissions"`
	Owner       string   `json:"owner"`
	Options     []string `json:"options,omitempty"`
	Secure      bool     `json:"secure"`
	Anomalies   []string `json:"anomalies,omitempty"`
}

// CyberpunkScan represents a cyberpunk-themed security scan
type CyberpunkScan struct {
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Duration    string    `json:"duration"`
	Findings    int       `json:"findings"`
	Status      string    `json:"status"`
	ThreatLevel string    `json:"threat_level"`
}

// HasCriticalVulnerabilities returns true if there are critical security vulnerabilities
func (r *Results) HasCriticalVulnerabilities() bool {
	return r.Summary.CriticalIssues > 0
}

// HasExploitableVulnerabilities returns true if there are exploitable vulnerabilities
func (r *Results) HasExploitableVulnerabilities() bool {
	return r.Summary.ExploitableVulns > 0
}

// GetThreatLevel calculates overall system threat level
func (r *Results) GetThreatLevel() string {
	if r.Summary.CriticalIssues > 0 {
		return "CRITICAL"
	} else if r.Summary.ExploitableVulns > 5 || r.Summary.HighIssues > 10 {
		return "HIGH"
	} else if r.Summary.HighIssues > 0 || r.Summary.MediumIssues > 15 {
		return "MODERATE"
	} else if r.Summary.MediumIssues > 0 || r.Summary.LowIssues > 20 {
		return "LOW"
	}
	return "MINIMAL"
}

// AddFinding adds a cyberpunk-enhanced finding to the results
func (r *Results) AddFinding(finding *Finding) {
	finding.Timestamp = time.Now()

	// Calculate threat score
	finding.ThreatScore = r.calculateThreatScore(finding)

	// Set cyberpunk flags
	r.setCyberpunkFlags(finding)

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

	// Update cyberpunk counters
	if finding.Exploitable {
		r.Summary.ExploitableVulns++
	}
	if finding.NeuralThreat {
		r.Summary.NeuralThreats++
	}
	if finding.ICEBypass {
		r.Summary.ICEBypasses++
	}
	if finding.GhostAccess {
		r.Summary.GhostAccesses++
	}
	if finding.MatrixAnomaly {
		r.Summary.MatrixAnomalies++
	}
}

// calculateThreatScore calculates threat score for a finding
func (r *Results) calculateThreatScore(finding *Finding) float64 {
	baseScore := 0.0

	switch finding.Severity {
	case SeverityCritical:
		baseScore = 10.0
	case SeverityHigh:
		baseScore = 7.5
	case SeverityMedium:
		baseScore = 5.0
	case SeverityLow:
		baseScore = 2.5
	case SeverityInfo:
		baseScore = 1.0
	}

	// Multiply by exploitability
	if finding.Exploitable {
		baseScore *= 1.5
	}

	// Add status modifier
	switch finding.Status {
	case StatusFail:
		baseScore *= 1.0
	case StatusWarn:
		baseScore *= 0.7
	case StatusPass:
		baseScore *= 0.1
	default:
		baseScore *= 0.5
	}

	return baseScore
}

// setCyberpunkFlags sets cyberpunk-specific flags based on category
func (r *Results) setCyberpunkFlags(finding *Finding) {
	switch finding.Category {
	case "Neural Pathways":
		finding.NeuralThreat = finding.Status == StatusFail
	case "ICE Barriers":
		finding.ICEBypass = finding.Status == StatusFail && finding.Exploitable
	case "Ghost Protocol":
		finding.GhostAccess = finding.Status == StatusFail && finding.Exploitable
	case "Filesystem Matrix":
		finding.MatrixAnomaly = finding.Status == StatusFail
	}

	// Set detection method
	if finding.DetectionMethod == "" {
		finding.DetectionMethod = "Neural Interface Scan"
	}
}

// GetCriticalFindings returns all critical severity findings
func (r *Results) GetCriticalFindings() []*Finding {
	var critical []*Finding
	for _, finding := range r.Findings {
		if finding.Severity == SeverityCritical {
			critical = append(critical, finding)
		}
	}
	return critical
}

// GetExploitableFindings returns all exploitable findings
func (r *Results) GetExploitableFindings() []*Finding {
	var exploitable []*Finding
	for _, finding := range r.Findings {
		if finding.Exploitable {
			exploitable = append(exploitable, finding)
		}
	}
	return exploitable
}

// GenerateSecurityScore calculates overall security score (0-100)
func (r *Results) GenerateSecurityScore() float64 {
	if r.Summary.TotalChecks == 0 {
		return 0.0
	}

	maxScore := float64(r.Summary.TotalChecks * 100)
	currentScore := float64(r.Summary.PassedChecks*100 + r.Summary.WarningChecks*50)

	// Apply penalties for critical issues
	penalty := float64(r.Summary.CriticalIssues * 20)
	penalty += float64(r.Summary.HighIssues * 10)
	penalty += float64(r.Summary.ExploitableVulns * 15)

	score := (currentScore - penalty) / maxScore * 100
	if score < 0 {
		score = 0
	}

	r.SecurityScore = score
	return score
}

// String returns a cyberpunk-styled string representation of the finding
func (f *Finding) String() string {
	exploitFlag := ""
	if f.Exploitable {
		exploitFlag = " [EXPLOITABLE]"
	}

	return fmt.Sprintf("[%s] %s: %s (%s)%s", f.Status, f.Severity, f.Title, f.ID, exploitFlag)
}

// GetCyberpunkSummary returns a cyberpunk-themed summary string
func (r *Results) GetCyberpunkSummary() string {
	threatLevel := r.GetThreatLevel()
	securityScore := r.GenerateSecurityScore()

	return fmt.Sprintf(`◢◤ NEURAL SECURITY ASSESSMENT COMPLETE
├─ Threat Level: %s
├─ Security Score: %.1f/100
├─ Total Vulnerabilities: %d
├─ Exploitable: %d
├─ Neural Threats: %d
├─ ICE Bypasses: %d
├─ Ghost Accesses: %d
└─ Matrix Anomalies: %d`,
		threatLevel, securityScore, len(r.Findings),
		r.Summary.ExploitableVulns, r.Summary.NeuralThreats,
		r.Summary.ICEBypasses, r.Summary.GhostAccesses,
		r.Summary.MatrixAnomalies)
}
