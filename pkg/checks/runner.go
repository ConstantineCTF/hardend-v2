package checks

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ConstantineCTF/hardend/pkg/config"
	"github.com/ConstantineCTF/hardend/pkg/utils"
	"github.com/fatih/color"
)

// Runner orchestrates all cyberpunk security checks with neural interface
type Runner struct {
	config    *config.Config
	logger    *utils.CyberpunkLogger
	stealth   bool
	ghostMode bool
	checkers  map[string]Checker
}

// Checker interface for all security check modules
type Checker interface {
	RunChecks(results *Results) error
}

// NewRunner creates a new cyberpunk security check runner
func NewRunner(cfg *config.Config, verbose, stealth, ghostMode bool) *Runner {
	r := &Runner{
		config:    cfg,
		logger:    utils.NewCyberpunkLogger(verbose, stealth),
		stealth:   stealth,
		ghostMode: ghostMode,
		checkers:  make(map[string]Checker),
	}

	// Initialize all cyberpunk checkers
	r.checkers["neural"] = NewNeuralChecker(verbose, stealth, ghostMode)
	r.checkers["ice"] = NewICEChecker(verbose, stealth, ghostMode)
	r.checkers["ghost"] = NewGhostChecker(verbose, stealth, ghostMode)
	r.checkers["matrix"] = NewMatrixChecker(verbose, stealth, ghostMode)

	// TODO: Initialize remaining checkers
	// r.checkers["net"] = NewNetChecker(verbose, stealth, ghostMode)
	// r.checkers["users"] = NewUsersChecker(verbose, stealth, ghostMode)
	// r.checkers["perms"] = NewPermsChecker(verbose, stealth, ghostMode)
	// r.checkers["suid"] = NewSUIDChecker(verbose, stealth, ghostMode)
	// r.checkers["packages"] = NewPackagesChecker(verbose, stealth, ghostMode)
	// r.checkers["logs"] = NewLogsChecker(verbose, stealth, ghostMode)
	// r.checkers["firewall"] = NewFirewallChecker(verbose, stealth, ghostMode)
	// r.checkers["selinux"] = NewSELinuxChecker(verbose, stealth, ghostMode)
	// r.checkers["cron"] = NewCronChecker(verbose, stealth, ghostMode)
	// r.checkers["boot"] = NewBootChecker(verbose, stealth, ghostMode)

	return r
}

// RunFullPenetrationSuite executes comprehensive security penetration testing
func (r *Runner) RunFullPenetrationSuite() (*Results, error) {
	scanTypes := []string{"neural", "ice", "ghost", "matrix"}
	return r.RunSelectedScans(scanTypes, r.stealth)
}

// RunSelectedScans executes specific security scans with cyberpunk styling
func (r *Runner) RunSelectedScans(scanTypes []string, stealthMode bool) (*Results, error) {
	startTime := time.Now()

	// Initialize results with cyberpunk neural interface
	results := &Results{
		SystemInfo: r.getNeuralSystemInfo(),
		Findings:   make([]*Finding, 0),
		Summary:    Summary{},
		StartTime:  startTime,
	}

	r.logger.Info("◢◤ Neural interface initialized - beginning penetration protocol")
	r.logger.Info("◢◤ Target system: %s (%s %s)", results.SystemInfo.Hostname,
		results.SystemInfo.OS, results.SystemInfo.Architecture)

	if r.ghostMode {
		r.logger.Info("◢◤ Ghost in the shell mode activated")
		utils.MatrixEffect(1 * time.Second)
	}

	// Execute security scans in cyberpunk style
	for _, scanType := range scanTypes {
		checker, exists := r.checkers[scanType]
		if !exists {
			r.logger.Warning("Unknown scan module '%s' - neural pathway not found", scanType)
			continue
		}

		r.logger.Info("◢◤ Initializing %s security protocol...", strings.ToUpper(scanType))

		if !r.stealth {
			// Show scanning animation
			scanName := r.getScanDisplayName(scanType)
			utils.ProgressBar(fmt.Sprintf("Executing %s scan", scanName),
				time.Duration(500+len(scanType)*100)*time.Millisecond)
		}

		// Execute the security check
		if err := checker.RunChecks(results); err != nil {
			r.logger.Error("Neural pathway error in %s scanner: %v", scanType, err)
			continue
		}

		r.logger.Debug("◢◤ %s scan completed successfully", strings.ToUpper(scanType))
	}

	// Finalize results with neural processing
	endTime := time.Now()
	results.EndTime = endTime
	results.Duration = endTime.Sub(startTime).String()

	// Perform final threat assessment
	r.performThreatAssessment(results)

	r.logger.Info("◢◤ Penetration testing complete - %d vulnerabilities identified", len(results.Findings))
	r.logger.Info("◢◤ Assessment duration: %s", results.Duration)

	if results.HasCriticalVulnerabilities() && !r.stealth {
		r.logger.Critical("CRITICAL VULNERABILITIES DETECTED - IMMEDIATE ACTION REQUIRED")
		// Add glitch effect for critical issues
		color.New(color.FgRed, color.Bold, color.BlinkRapid).Printf("    ◢◤ SYSTEM COMPROMISED ◢◤\n")
	}

	return results, nil
}

// getNeuralSystemInfo gathers comprehensive system intelligence
func (r *Runner) getNeuralSystemInfo() SystemInfo {
	hostname, osType, arch := utils.GetSystemInfo()

	// Get enhanced system information
	kernel := "unknown"
	if output, err := utils.ExecuteCommand("uname", "-r"); err == nil {
		kernel = strings.TrimSpace(output)
	}

	uptime := "unknown"
	if r.stealth {
		// In stealth mode, try to get uptime without leaving traces
		if output, err := utils.StealthExecute("cat", "/proc/uptime"); err == nil {
			fields := strings.Fields(output)
			if len(fields) > 0 {
				uptime = fmt.Sprintf("%.0f seconds", parseFloat(fields[0]))
			}
		}
	} else {
		if output, err := utils.ExecuteCommand("uptime", "-p"); err == nil {
			uptime = strings.TrimSpace(output)
		}
	}

	// Get additional neural interface data
	loadAvg := "unknown"
	if output, err := utils.GetSystemLoad(); err == nil {
		loadAvg = strings.TrimSpace(output)
	}

	return SystemInfo{
		Hostname:     hostname,
		OS:           osType,
		Kernel:       kernel,
		Architecture: arch,
		Uptime:       uptime,
		LoadAverage:  loadAvg,
		CPUCores:     runtime.NumCPU(),
		MemoryInfo:   r.getMemoryInfo(),
	}
}

// getMemoryInfo retrieves system memory information
func (r *Runner) getMemoryInfo() string {
	if r.stealth {
		// Read /proc/meminfo in stealth mode
		if content, err := utils.ReadLines("/proc/meminfo"); err == nil {
			for _, line := range content {
				if strings.HasPrefix(line, "MemTotal:") {
					return strings.TrimSpace(line)
				}
			}
		}
	} else {
		if output, err := utils.ExecuteCommand("free", "-h"); err == nil {
			lines := strings.Split(output, "\n")
			if len(lines) > 1 {
				return strings.TrimSpace(lines[1])
			}
		}
	}
	return "unknown"
}

// performThreatAssessment analyzes overall security posture
func (r *Runner) performThreatAssessment(results *Results) {
	r.logger.Debug("◢◤ Performing neural threat assessment...")

	// Calculate threat metrics
	totalVulns := len(results.Findings)
	criticalVulns := results.Summary.CriticalIssues
	highVulns := results.Summary.HighIssues

	// Assess threat level
	threatLevel := "MINIMAL"
	if criticalVulns > 0 {
		threatLevel = "CRITICAL"
	} else if highVulns > 5 {
		threatLevel = "HIGH"
	} else if highVulns > 0 || results.Summary.MediumIssues > 10 {
		threatLevel = "MODERATE"
	}

	// Add threat assessment finding
	finding := &Finding{
		ID:          "NEURAL_THREAT_ASSESSMENT",
		Title:       fmt.Sprintf("Overall threat level: %s", threatLevel),
		Description: fmt.Sprintf("Comprehensive security posture assessment based on %d findings", totalVulns),
		Severity:    r.getThreatSeverity(threatLevel),
		Status:      r.getThreatStatus(threatLevel),
		Expected:    "MINIMAL threat level",
		Actual:      threatLevel,
		Category:    "Threat Assessment",
		Timestamp:   time.Now(),
	}
	results.AddFinding(finding)

	// Add system hardening score
	maxScore := float64(results.Summary.TotalChecks * 100)
	currentScore := float64(results.Summary.PassedChecks*100 + results.Summary.WarningChecks*50)
	hardeningScore := currentScore / maxScore * 100

	finding = &Finding{
		ID:          "NEURAL_HARDENING_SCORE",
		Title:       fmt.Sprintf("System hardening score: %.1f%%", hardeningScore),
		Description: "Overall system security hardening effectiveness",
		Severity:    r.getScoreSeverity(hardeningScore),
		Status:      r.getScoreStatus(hardeningScore),
		Expected:    ">= 90% hardening score",
		Actual:      fmt.Sprintf("%.1f%%", hardeningScore),
		Category:    "Threat Assessment",
		Timestamp:   time.Now(),
	}
	results.AddFinding(finding)
}

// getScanDisplayName returns cyberpunk display name for scan type
func (r *Runner) getScanDisplayName(scanType string) string {
	displayNames := map[string]string{
		"neural":   "Neural Pathways",
		"ice":      "ICE Barriers",
		"ghost":    "Ghost Protocol",
		"matrix":   "Filesystem Matrix",
		"net":      "Network Intrusion",
		"users":    "User Access Control",
		"perms":    "Permission Matrix",
		"suid":     "Privilege Escalation",
		"packages": "Software Vulnerabilities",
		"logs":     "Forensic Analysis",
		"firewall": "Perimeter Defense",
		"selinux":  "Mandatory Access Control",
		"cron":     "Scheduled Tasks",
		"boot":     "Boot Sequence",
	}

	if name, exists := displayNames[scanType]; exists {
		return name
	}
	return strings.ToTitle(scanType)
}

// Helper functions for threat assessment

func (r *Runner) getThreatSeverity(threatLevel string) Severity {
	switch threatLevel {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MODERATE":
		return SeverityMedium
	default:
		return SeverityInfo
	}
}

func (r *Runner) getThreatStatus(threatLevel string) CheckStatus {
	switch threatLevel {
	case "CRITICAL", "HIGH":
		return StatusFail
	case "MODERATE":
		return StatusWarn
	default:
		return StatusPass
	}
}

func (r *Runner) getScoreSeverity(score float64) Severity {
	if score < 50 {
		return SeverityCritical
	} else if score < 70 {
		return SeverityHigh
	} else if score < 85 {
		return SeverityMedium
	} else {
		return SeverityLow
	}
}

func (r *Runner) getScoreStatus(score float64) CheckStatus {
	if score < 70 {
		return StatusFail
	} else if score < 85 {
		return StatusWarn
	} else {
		return StatusPass
	}
}

// parseFloat safely parses a float string
func parseFloat(s string) float64 {
	if val, err := strconv.ParseFloat(s, 64); err == nil {
		return val
	}
	return 0.0
}
