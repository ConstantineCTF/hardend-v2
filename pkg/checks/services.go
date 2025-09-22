package checks

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ConstantineCTF/hardend/pkg/utils"
	"github.com/fatih/color"
)

// ICEChecker handles Intrusion Countermeasures Electronics (Services)
type ICEChecker struct {
	logger   *utils.CyberpunkLogger
	stealth  bool
	advanced bool
}

// NewICEChecker creates a new ICE system analyzer
func NewICEChecker(verbose, stealth, advanced bool) *ICEChecker {
	return &ICEChecker{
		logger:   utils.NewCyberpunkLogger(verbose, stealth),
		stealth:  stealth,
		advanced: advanced,
	}
}

// ICERule defines an intrusion countermeasure rule
type ICERule struct {
	ServiceName  string
	ShouldRun    bool
	Description  string
	Severity     Severity
	References   []string
	ThreatLevel  string
	Exploitable  bool
	AttackVector string
}

// RunChecks performs comprehensive ICE system analysis
func (ic *ICEChecker) RunChecks(results *Results) error {
	ic.logger.Info("◢◤ Activating ICE countermeasures scan...")

	if !ic.stealth {
		utils.ProgressBar("Analyzing ICE barriers", 1500*time.Millisecond)
	}

	// Core ICE barrier analysis
	rules := ic.getICERules()
	for _, rule := range rules {
		ic.logger.Debug("Scanning ICE barrier: %s", rule.ServiceName)

		isRunning, isEnabled, err := ic.analyzeICEBarrier(rule.ServiceName)
		if err != nil {
			finding := &Finding{
				ID:          fmt.Sprintf("ICE_%s_ERROR", strings.ToUpper(rule.ServiceName)),
				Title:       fmt.Sprintf("ICE barrier %s analysis failed", rule.ServiceName),
				Description: fmt.Sprintf("Unable to analyze ICE barrier %s - potential system compromise", rule.ServiceName),
				Severity:    SeverityMedium,
				Status:      StatusSkip,
				Expected:    "barrier analysis",
				Actual:      fmt.Sprintf("SCAN_ERROR: %v", err),
				Category:    "ICE Barriers",
				References:  rule.References,
			}
			results.AddFinding(finding)
			continue
		}

		status := StatusPass
		threat := "SECURED"

		if rule.ShouldRun {
			if !isRunning || !isEnabled {
				status = StatusFail
				threat = "VULNERABLE"
			}
		} else {
			if isRunning || isEnabled {
				status = StatusFail
				threat = rule.ThreatLevel
			}
		}

		finding := &Finding{
			ID:          fmt.Sprintf("ICE_%s", strings.ToUpper(rule.ServiceName)),
			Title:       fmt.Sprintf("ICE %s [%s]", rule.ServiceName, threat),
			Description: rule.Description,
			Severity:    rule.Severity,
			Status:      status,
			Expected:    fmt.Sprintf("running: %t, enabled: %t", rule.ShouldRun, rule.ShouldRun),
			Actual:      fmt.Sprintf("running: %t, enabled: %t", isRunning, isEnabled),
			Remediation: ic.getICERemediation(rule.ServiceName, rule.ShouldRun, rule.AttackVector),
			Category:    "ICE Barriers",
			References:  rule.References,
			Exploitable: rule.Exploitable,
		}
		results.AddFinding(finding)
	}

	// Advanced ICE analysis
	if ic.advanced {
		ic.performAdvancedICEAnalysis(results)
	}

	// Backdoor service detection
	ic.detectBackdoorServices(results)

	// Process hollowing detection
	ic.detectProcessHollowing(results)

	ic.logger.Info("◢◤ ICE barrier scan complete - %d barriers analyzed", len(rules))
	return nil
}

// analyzeICEBarrier checks the status of an ICE barrier (service)
func (ic *ICEChecker) analyzeICEBarrier(serviceName string) (bool, bool, error) {
	var isRunning, isEnabled bool
	var err error

	if ic.stealth {
		// Stealth mode - use proc filesystem
		isRunning = utils.CheckProcessRunning(serviceName)
		// In stealth mode, we can't easily check if service is enabled
		isEnabled = isRunning // Assume if running, it's enabled
	} else {
		// Normal mode - use systemctl
		output, err := utils.ExecuteCommand("systemctl", "is-active", serviceName)
		isRunning = err == nil && strings.TrimSpace(output) == "active"

		output, err = utils.ExecuteCommand("systemctl", "is-enabled", serviceName)
		isEnabled = err == nil && strings.TrimSpace(output) == "enabled"
	}

	return isRunning, isEnabled, err
}

// getICERules returns comprehensive ICE barrier security rules
func (ic *ICEChecker) getICERules() []ICERule {
	return []ICERule{
		// Critical threat services that should be DISABLED
		{
			ServiceName:  "telnet",
			ShouldRun:    false,
			Description:  "Telnet daemon - unencrypted protocol breach",
			Severity:     SeverityCritical,
			References:   []string{"CIS 2.1.1", "NIST IA-5"},
			ThreatLevel:  "CRITICAL_BREACH",
			Exploitable:  true,
			AttackVector: "plaintext credential harvesting, MitM attacks",
		},
		{
			ServiceName:  "rsh",
			ShouldRun:    false,
			Description:  "Remote shell daemon - legacy attack vector",
			Severity:     SeverityCritical,
			References:   []string{"CIS 2.1.2"},
			ThreatLevel:  "CRITICAL_BREACH",
			Exploitable:  true,
			AttackVector: "remote code execution, credential theft",
		},
		{
			ServiceName:  "rlogin",
			ShouldRun:    false,
			Description:  "Remote login daemon - authentication bypass risk",
			Severity:     SeverityCritical,
			References:   []string{"CIS 2.1.3"},
			ThreatLevel:  "CRITICAL_BREACH",
			Exploitable:  true,
			AttackVector: ".rhosts exploitation, trust relationship abuse",
		},
		{
			ServiceName:  "rexec",
			ShouldRun:    false,
			Description:  "Remote exec daemon - direct command execution",
			Severity:     SeverityCritical,
			References:   []string{"CIS 2.1.4"},
			ThreatLevel:  "CRITICAL_BREACH",
			Exploitable:  true,
			AttackVector: "arbitrary command execution",
		},
		{
			ServiceName:  "nis",
			ShouldRun:    false,
			Description:  "Network Information Service - weak authentication",
			Severity:     SeverityHigh,
			References:   []string{"CIS 2.1.5"},
			ThreatLevel:  "HIGH_RISK",
			Exploitable:  true,
			AttackVector: "password database enumeration",
		},
		{
			ServiceName:  "ntalk",
			ShouldRun:    false,
			Description:  "Network talk daemon - information disclosure",
			Severity:     SeverityMedium,
			References:   []string{"CIS 2.1.6"},
			ThreatLevel:  "MEDIUM_RISK",
			Exploitable:  false,
			AttackVector: "information gathering",
		},
		{
			ServiceName:  "xinetd",
			ShouldRun:    false,
			Description:  "Extended internet daemon - legacy service launcher",
			Severity:     SeverityHigh,
			References:   []string{"CIS 2.1.7"},
			ThreatLevel:  "HIGH_RISK",
			Exploitable:  true,
			AttackVector: "service enumeration, legacy protocol exploitation",
		},
		{
			ServiceName:  "avahi-daemon",
			ShouldRun:    false,
			Description:  "Avahi mDNS/DNS-SD daemon - service discovery leak",
			Severity:     SeverityLow,
			References:   []string{"CIS 2.2.3"},
			ThreatLevel:  "LOW_RISK",
			Exploitable:  false,
			AttackVector: "network reconnaissance",
		},
		{
			ServiceName:  "cups",
			ShouldRun:    false,
			Description:  "Print service daemon - unnecessary attack surface",
			Severity:     SeverityLow,
			References:   []string{"CIS 2.2.4"},
			ThreatLevel:  "LOW_RISK",
			Exploitable:  false,
			AttackVector: "local privilege escalation",
		},
		{
			ServiceName:  "dhcpd",
			ShouldRun:    false,
			Description:  "DHCP server daemon - network manipulation risk",
			Severity:     SeverityMedium,
			References:   []string{"CIS 2.2.5"},
			ThreatLevel:  "MEDIUM_RISK",
			Exploitable:  true,
			AttackVector: "DHCP spoofing, network redirection",
		},
		// Critical services that SHOULD be running
		{
			ServiceName:  "sshd",
			ShouldRun:    true,
			Description:  "SSH daemon - secure remote access barrier",
			Severity:     SeverityHigh,
			References:   []string{"CIS 5.2.1"},
			ThreatLevel:  "SECURED",
			Exploitable:  false,
			AttackVector: "properly configured SSH is secure",
		},
		{
			ServiceName:  "ntp",
			ShouldRun:    true,
			Description:  "Network Time Protocol - temporal sync barrier",
			Severity:     SeverityMedium,
			References:   []string{"CIS 2.2.1.1"},
			ThreatLevel:  "TIME_SYNC",
			Exploitable:  false,
			AttackVector: "time-based attacks without sync",
		},
		{
			ServiceName:  "chronyd",
			ShouldRun:    true,
			Description:  "Chrony time daemon - alternative temporal barrier",
			Severity:     SeverityMedium,
			References:   []string{"CIS 2.2.1.2"},
			ThreatLevel:  "TIME_SYNC",
			Exploitable:  false,
			AttackVector: "time-based attacks without sync",
		},
		{
			ServiceName:  "auditd",
			ShouldRun:    true,
			Description:  "Audit daemon - forensic logging barrier",
			Severity:     SeverityHigh,
			References:   []string{"CIS 4.1.1.1"},
			ThreatLevel:  "LOGGING",
			Exploitable:  false,
			AttackVector: "evidence tampering without auditing",
		},
		{
			ServiceName:  "fail2ban",
			ShouldRun:    true,
			Description:  "Intrusion prevention system - active defense barrier",
			Severity:     SeverityMedium,
			References:   []string{"Security Best Practice"},
			ThreatLevel:  "ACTIVE_DEFENSE",
			Exploitable:  false,
			AttackVector: "brute force attacks",
		},
	}
}

// performAdvancedICEAnalysis conducts deep ICE system analysis
func (ic *ICEChecker) performAdvancedICEAnalysis(results *Results) {
	ic.logger.Debug("Performing advanced ICE barrier analysis...")

	// Analyze listening ports and services
	ic.analyzeNetworkListeners(results)

	// Check for service dependencies
	ic.analyzeServiceDependencies(results)

	// Detect unusual service configurations
	ic.detectUnusualConfigurations(results)
}

// analyzeNetworkListeners checks for services listening on network ports
func (ic *ICEChecker) analyzeNetworkListeners(results *Results) {
	output, err := utils.ExecuteCommand("ss", "-tuln")
	if err != nil {
		output, err = utils.ExecuteCommand("netstat", "-tuln")
		if err != nil {
			return
		}
	}

	lines := strings.Split(output, "\n")
	listeners := make(map[string][]string)

	for _, line := range lines {
		if strings.Contains(line, "LISTEN") || strings.Contains(line, "State") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				proto := fields[0]
				address := fields[3]
				listeners[proto] = append(listeners[proto], address)
			}
		}
	}

	// Analyze suspicious ports
	suspiciousPorts := []string{":23", ":513", ":514", ":515", ":512", ":1999", ":31337", ":12345"}

	for proto, addresses := range listeners {
		for _, addr := range addresses {
			for _, suspPort := range suspiciousPorts {
				if strings.Contains(addr, suspPort) {
					finding := &Finding{
						ID:          fmt.Sprintf("ICE_SUSPICIOUS_PORT_%x", sha256.Sum256([]byte(addr))),
						Title:       fmt.Sprintf("Suspicious port listener detected"),
						Description: fmt.Sprintf("Service listening on suspicious port: %s (%s)", addr, proto),
						Severity:    SeverityHigh,
						Status:      StatusFail,
						Expected:    "no suspicious listeners",
						Actual:      fmt.Sprintf("%s listening on %s", proto, addr),
						Category:    "ICE Barriers",
						Exploitable: true,
					}
					results.AddFinding(finding)
				}
			}
		}
	}
}

// detectBackdoorServices looks for potential backdoor services
func (ic *ICEChecker) detectBackdoorServices(results *Results) {
	backdoorNames := []string{
		"backdoor", "rootkit", "nc", "netcat", "socat",
		"cryptcat", "reverse", "shell", "bind", "trojan",
	}

	processes, err := utils.ExecuteCommand("ps", "aux")
	if err != nil {
		return
	}

	lines := strings.Split(processes, "\n")
	for _, line := range lines {
		processLower := strings.ToLower(line)
		for _, backdoor := range backdoorNames {
			if strings.Contains(processLower, backdoor) &&
				!strings.Contains(processLower, "grep") {
				finding := &Finding{
					ID:          fmt.Sprintf("ICE_BACKDOOR_%x", sha256.Sum256([]byte(line))),
					Title:       "Potential backdoor process detected",
					Description: "Suspicious process name suggests backdoor activity",
					Severity:    SeverityCritical,
					Status:      StatusFail,
					Expected:    "no backdoor processes",
					Actual:      line,
					Category:    "ICE Barriers",
					Exploitable: true,
				}
				results.AddFinding(finding)
				break
			}
		}
	}
}

// detectProcessHollowing checks for process hollowing indicators
func (ic *ICEChecker) detectProcessHollowing(results *Results) {
	// Check for processes with suspicious memory mappings
	processes, err := utils.ExecuteCommand("ps", "-eo", "pid,comm,cmd")
	if err != nil {
		return
	}

	lines := strings.Split(processes, "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pid := fields[0]
			comm := fields[1]

			// Check if process name differs significantly from command
			if len(fields) >= 3 {
				cmd := strings.Join(fields[2:], " ")
				if !strings.Contains(cmd, comm) && comm != "[" && !strings.HasPrefix(comm, "[") {
					finding := &Finding{
						ID:          fmt.Sprintf("ICE_PROCESS_HOLLOW_%s", pid),
						Title:       fmt.Sprintf("Potential process hollowing: PID %s", pid),
						Description: "Process name doesn't match command - possible hollowing",
						Severity:    SeverityHigh,
						Status:      StatusWarn,
						Expected:    "process name matches command",
						Actual:      fmt.Sprintf("comm: %s, cmd: %s", comm, cmd),
						Category:    "ICE Barriers",
						Exploitable: true,
					}
					results.AddFinding(finding)
				}
			}
		}
	}
}

// analyzeServiceDependencies checks service dependency chains
func (ic *ICEChecker) analyzeServiceDependencies(results *Results) {
	// This is a placeholder for service dependency analysis
	// Would require parsing systemctl list-dependencies output

	finding := &Finding{
		ID:          "ICE_DEPENDENCY_ANALYSIS",
		Title:       "ICE barrier dependency analysis",
		Description: "Service dependency chain security assessment",
		Severity:    SeverityInfo,
		Status:      StatusInfo,
		Expected:    "minimal dependencies",
		Actual:      "requires detailed analysis",
		Category:    "ICE Barriers",
	}
	results.AddFinding(finding)
}

// detectUnusualConfigurations checks for suspicious service configurations
func (ic *ICEChecker) detectUnusualConfigurations(results *Results) {
	// Check for services running as root unnecessarily
	processes, err := utils.ExecuteCommand("ps", "-eo", "user,pid,comm")
	if err != nil {
		return
	}

	rootProcesses := 0
	lines := strings.Split(processes, "\n")

	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "root" {
			rootProcesses++
		}
	}

	status := StatusInfo
	if rootProcesses > 50 {
		status = StatusWarn
	}

	finding := &Finding{
		ID:          "ICE_ROOT_PROCESSES",
		Title:       fmt.Sprintf("Root processes running: %d", rootProcesses),
		Description: "Number of processes running with root privileges",
		Severity:    SeverityLow,
		Status:      status,
		Expected:    "minimal root processes",
		Actual:      fmt.Sprintf("%d root processes", rootProcesses),
		Category:    "ICE Barriers",
	}
	results.AddFinding(finding)
}

// getICERemediation returns remediation for ICE barrier issues
func (ic *ICEChecker) getICERemediation(serviceName string, shouldRun bool, attackVector string) string {
	if shouldRun {
		return fmt.Sprintf(`◢◤ ICE BARRIER ACTIVATION:
┌─ Enable: systemctl enable %s
├─ Start: systemctl start %s
├─ Verify: systemctl status %s
└─ Monitor: journalctl -u %s -f`,
			serviceName, serviceName, serviceName, serviceName)
	} else {
		return fmt.Sprintf(`◢◤ ICE BARRIER DEACTIVATION:
┌─ Stop: systemctl stop %s
├─ Disable: systemctl disable %s
├─ Mask: systemctl mask %s
├─ Verify: systemctl is-active %s
└─ Attack Vector Blocked: %s`,
			serviceName, serviceName, serviceName, serviceName, attackVector)
	}
}
