package checks

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ConstantineCTF/hardend/pkg/config"
	"github.com/ConstantineCTF/hardend/pkg/utils" // Ensure this import path is correct
)

// Runner orchestrates all security checks
type Runner struct {
	config   *config.Config
	logger   *utils.Logger // Corrected: Use Logger
	stealth  bool
	checkers map[string]Checker
}

// Checker interface for all security check modules
type Checker interface {
	RunChecks(results *Results) error
}

// NewRunner creates a new security check runner
func NewRunner(cfg *config.Config, verbose, stealth bool) *Runner {
	r := &Runner{
		config:   cfg,
		logger:   utils.NewLogger(verbose, stealth), // Corrected: Use NewLogger
		stealth:  stealth,
		checkers: make(map[string]Checker),
	}

	// Initialize all checkers using corrected names and passing config flags
	advanced := cfg.Scanning.AdvancedAnalysis
	if cfg.IsModuleEnabled("kernel") {
		r.checkers["kernel"] = NewKernelChecker(verbose, stealth, advanced)
	}
	if cfg.IsModuleEnabled("services") {
		r.checkers["services"] = NewServicesChecker(verbose, stealth, advanced)
	}
	if cfg.IsModuleEnabled("ssh") {
		// SSH checker doesn't currently use 'advanced' flag internally in refactored version
		r.checkers["ssh"] = NewSSHChecker(verbose, stealth)
	}
	if cfg.IsModuleEnabled("filesystem") {
		r.checkers["filesystem"] = NewFilesystemChecker(verbose, stealth, advanced)
	}

	// TODO: Initialize remaining checkers as they are built and enabled in config
	// if cfg.IsModuleEnabled("network") {
	//     r.checkers["network"] = NewNetworkChecker(verbose, stealth, advanced)
	// }
	// if cfg.IsModuleEnabled("users") {
	//     r.checkers["users"] = NewUsersChecker(verbose, stealth, advanced)
	// }
	// ... etc.

	r.logger.Debug("Initialized checkers for enabled modules.")
	return r
}

// RunFullPenetrationSuite executes all security checks enabled in the configuration
func (r *Runner) RunFullPenetrationSuite() (*Results, error) {
	// Get all enabled modules directly from the initialized checkers map keys
	scanTypes := make([]string, 0, len(r.checkers))
	for k := range r.checkers {
		scanTypes = append(scanTypes, k)
	}
	r.logger.Info("Running full assessment suite for modules: %v", scanTypes)
	return r.RunSelectedScans(scanTypes, r.stealth)
}

// RunSelectedScans executes specific security scans if they are initialized
func (r *Runner) RunSelectedScans(scanTypes []string, stealthMode bool) (*Results, error) {
	startTime := time.Now()

	results := &Results{
		SystemInfo: r.getSystemInfo(),
		Findings:   make([]*Finding, 0),
		Summary:    Summary{}, // Initialize summary counters to zero
		StartTime:  startTime,
	}

	r.logger.Info("Starting security assessment...")
	r.logger.Info("Target system: %s (%s %s)", results.SystemInfo.Hostname,
		results.SystemInfo.OS, results.SystemInfo.Architecture)

	// Execute security scans
	executedCount := 0
	for _, scanType := range scanTypes {
		checker, exists := r.checkers[scanType]
		if !exists {
			// This case should ideally not happen if scanTypes comes from initialized checkers,
			// but handle defensively if user provided invalid types via flags.
			r.logger.Warning("Scan module '%s' is not available or enabled - skipping.", scanType)
			continue
		}

		scanName := r.getScanDisplayName(scanType)
		r.logger.Info("Executing %s scan...", scanName)

		// Run the checks for the module
		err := checker.RunChecks(results)
		executedCount++

		if err != nil {
			// Log the error returned by the checker's RunChecks method
			r.logger.Error("Error during %s scan: %v", scanType, err)
			// Decide if error should halt execution or just be logged
			// For now, continue with other checks
			// Optionally add a finding about the module failure
			moduleErrorFinding := &Finding{
				ID:          fmt.Sprintf("MODULE_ERROR_%s", strings.ToUpper(scanType)),
				Title:       fmt.Sprintf("Error executing %s module", scanName),
				Description: fmt.Sprintf("The %s scan failed to complete: %v", scanName, err),
				Severity:    SeverityHigh, // Module failure is usually significant
				Status:      StatusSkip,
				Category:    "Assessment Framework",
			}
			results.AddFinding(moduleErrorFinding)
			continue // Continue to next module
		}

		r.logger.Debug("%s scan completed successfully.", scanName)
	}

	// Finalize results
	endTime := time.Now()
	results.EndTime = endTime
	results.Duration = endTime.Sub(startTime).Round(time.Millisecond).String() // Nicer duration format

	r.logger.Info("Assessment complete. %d modules executed.", executedCount)
	r.logger.Info("Total findings: %d (Critical: %d, High: %d, Medium: %d, Low: %d)",
		results.Summary.FailedChecks+results.Summary.WarningChecks, // Approx total issues
		results.Summary.CriticalIssues, results.Summary.HighIssues,
		results.Summary.MediumIssues, results.Summary.LowIssues)
	r.logger.Info("Assessment duration: %s", results.Duration)

	if results.HasCriticalVulnerabilities() && !r.stealth {
		// Use logger.Error or logger.Critical for consistency
		r.logger.Error("CRITICAL VULNERABILITIES DETECTED - Review report for immediate action.")
	} else if results.Summary.FailedChecks > 0 && !r.stealth {
		r.logger.Warning("%d failed checks detected. Review report.", results.Summary.FailedChecks)
	}

	return results, nil
}

// getSystemInfo gathers comprehensive system information using utils
func (r *Runner) getSystemInfo() SystemInfo {
	hostname, osName, arch := utils.GetSystemInfo()
	kernel := utils.GetKernelVersion()

	// Attempt to get more specific OS Name/Version if possible (requires more complex parsing)
	// For now, osName from utils.GetSystemInfo() might just be "linux"
	fullOSName := osName // Placeholder, could try reading /etc/os-release

	var uptime string
	if r.stealth {
		// Try reading /proc/uptime stealthily
		if output, err := utils.StealthExecute("cat", "/proc/uptime"); err == nil {
			fields := strings.Fields(output)
			if len(fields) > 0 {
				uptimeSec, _ := strconv.ParseFloat(fields[0], 64)
				// Format duration more nicely
				uptimeDur := time.Duration(uptimeSec) * time.Second
				uptime = uptimeDur.String() // e.g., "1h2m3.456s"
			}
		}
	} else {
		// Use 'uptime -p' for pretty format if available
		if output, err := utils.ExecuteCommand("uptime", "-p"); err == nil {
			uptime = strings.TrimSpace(output)
		} else {
			// Fallback to standard uptime output if -p fails
			if output, err := utils.ExecuteCommand("uptime"); err == nil {
				uptime = strings.TrimSpace(output)
			}
		}
	}
	if uptime == "" {
		uptime = "unknown"
	}

	loadAvg := "unknown"
	// GetSystemLoad currently calls `uptime`, maybe parse specifically for load
	// Example parsing (simplified):
	if uptimeOutput, err := utils.GetSystemLoad(); err == nil {
		if idx := strings.Index(uptimeOutput, "load average:"); idx != -1 {
			loadAvg = strings.TrimSpace(uptimeOutput[idx+len("load average:"):])
		} else {
			loadAvg = "(Could not parse)"
		}
	}

	return SystemInfo{
		Hostname:     hostname,
		OS:           fullOSName, // Use potentially enhanced OS name
		Kernel:       kernel,
		Architecture: arch,
		Uptime:       uptime,
		LoadAverage:  loadAvg,
		CPUCores:     runtime.NumCPU(),
		MemoryInfo:   r.getMemoryInfo(),
	}
}

// getMemoryInfo retrieves system memory information from /proc/meminfo or 'free'
func (r *Runner) getMemoryInfo() string {
	memTotal := "unknown"
	memFree := "unknown"

	// Prefer reading /proc/meminfo directly as it's often more reliable than parsing 'free'
	meminfo, err := utils.ReadLines("/proc/meminfo")
	if err == nil {
		for _, line := range meminfo {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				key := fields[0]
				value := fields[1]
				unit := ""
				if len(fields) > 2 {
					unit = fields[2]
				}

				if key == "MemTotal:" {
					memTotal = value + " " + unit
				} else if key == "MemAvailable:" { // Prefer MemAvailable over MemFree
					memFree = value + " " + unit
					break // Found both, exit early
				} else if key == "MemFree:" && memFree == "unknown" { // Fallback to MemFree
					memFree = value + " " + unit
				}
			}
		}
		if memTotal != "unknown" && memFree != "unknown" {
			return fmt.Sprintf("Total: %s / Available: %s", memTotal, memFree)
		}
	} else {
		r.logger.Debug("Could not read /proc/meminfo: %v", err)
	}

	// Fallback to 'free -h' if /proc/meminfo failed and not in stealth
	if !r.stealth {
		if output, err := utils.ExecuteCommand("free", "-h"); err == nil {
			lines := strings.Split(output, "\n")
			if len(lines) > 1 {
				// Try to parse the 'Mem:' line (usually the second line)
				fields := strings.Fields(lines[1])
				if len(fields) > 1 && fields[0] == "Mem:" {
					// Extract Total and Available/Free, indices depend on 'free' version
					// This is fragile, /proc/meminfo is better
					if len(fields) >= 7 { // Assuming modern 'free' output
						return fmt.Sprintf("Total: %s / Available: %s", fields[1], fields[6])
					} else if len(fields) >= 4 { // Older 'free' might have different columns
						return fmt.Sprintf("Total: %s / Free: %s", fields[1], fields[3])
					}
				}
				// If parsing fails, return the raw line
				return strings.TrimSpace(lines[1])
			}
		} else {
			r.logger.Debug("Could not execute 'free -h': %v", err)
		}
	}

	return "unknown" // If all methods fail
}

// getScanDisplayName returns a professional display name for a scan type
func (r *Runner) getScanDisplayName(scanType string) string {
	// Map internal names to user-friendly names
	displayNames := map[string]string{
		"kernel":     "Kernel Parameters",
		"services":   "System Services",
		"ssh":        "SSH Configuration",
		"filesystem": "Filesystem Mounts & Modules",
		"network":    "Network Configuration", // Future
		"users":      "User Accounts",         // Future
		"perms":      "File Permissions",      // Future
		"suid":       "SUID/SGID Binaries",    // Future
		"packages":   "Installed Packages",    // Future
		"logs":       "System Logs & Audit",   // Future
		"firewall":   "Firewall Rules",        // Future
		"selinux":    "SELinux/AppArmor",      // Future
		"cron":       "Scheduled Tasks",       // Future
		"boot":       "Boot Security",         // Future
	}

	if name, exists := displayNames[scanType]; exists {
		return name
	}
	// Fallback: Capitalize the internal name
	return strings.Title(scanType)
}
