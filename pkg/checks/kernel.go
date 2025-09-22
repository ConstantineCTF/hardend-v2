package checks

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ConstantineCTF/hardend/pkg/utils"
)

// NeuralChecker handles kernel neural pathway security analysis
type NeuralChecker struct {
	logger   *utils.CyberpunkLogger
	stealth  bool
	advanced bool
}

// NewNeuralChecker creates a new neural pathway analyzer
func NewNeuralChecker(verbose, stealth, advanced bool) *NeuralChecker {
	return &NeuralChecker{
		logger:   utils.NewCyberpunkLogger(verbose, stealth),
		stealth:  stealth,
		advanced: advanced,
	}
}

// NeuralRule defines a kernel neural pathway security rule
type NeuralRule struct {
	Parameter   string
	Expected    string
	Description string
	Severity    Severity
	References  []string
	Exploitable bool
	CVEIDs      []string
}

// RunChecks performs comprehensive neural pathway analysis
func (nc *NeuralChecker) RunChecks(results *Results) error {
	nc.logger.Info("◢◤ Initiating neural pathway scan...")

	if !nc.stealth {
		utils.ProgressBar("Analyzing kernel neural matrix", 1*time.Second)
	}

	// Core neural pathway checks
	rules := nc.getNeuralRules()
	for _, rule := range rules {
		nc.logger.Debug("Scanning neural pathway: %s", rule.Parameter)

		actual, err := nc.readNeuralPathway(rule.Parameter)
		if err != nil {
			finding := &Finding{
				ID:          fmt.Sprintf("NEURAL_%s", strings.ToUpper(strings.ReplaceAll(rule.Parameter, ".", "_"))),
				Title:       fmt.Sprintf("Neural pathway %s compromised", rule.Parameter),
				Description: fmt.Sprintf("Unable to access neural pathway %s - potential intrusion", rule.Parameter),
				Severity:    SeverityMedium,
				Status:      StatusSkip,
				Expected:    rule.Expected,
				Actual:      fmt.Sprintf("ACCESS_DENIED: %v", err),
				Remediation: nc.getNeuralRemediation(rule.Parameter, rule.Expected),
				Category:    "Neural Pathways",
				References:  rule.References,
				CVEIDs:      rule.CVEIDs,
				Exploitable: rule.Exploitable,
			}
			results.AddFinding(finding)
			continue
		}

		status := StatusPass
		threat := "SECURE"
		if actual != rule.Expected {
			status = StatusFail
			threat = "COMPROMISED"
			if rule.Exploitable {
				threat = "CRITICALLY_EXPLOITABLE"
			}
		}

		finding := &Finding{
			ID:          fmt.Sprintf("NEURAL_%s", strings.ToUpper(strings.ReplaceAll(rule.Parameter, ".", "_"))),
			Title:       fmt.Sprintf("Neural pathway %s [%s]", rule.Parameter, threat),
			Description: rule.Description,
			Severity:    rule.Severity,
			Status:      status,
			Expected:    rule.Expected,
			Actual:      actual,
			Remediation: nc.getNeuralRemediation(rule.Parameter, rule.Expected),
			Category:    "Neural Pathways",
			References:  rule.References,
			CVEIDs:      rule.CVEIDs,
			Exploitable: rule.Exploitable,
		}
		results.AddFinding(finding)
	}

	// Advanced neural analysis
	if nc.advanced {
		nc.performAdvancedNeuralAnalysis(results)
	}

	// Kernel module rootkit detection
	nc.detectKernelRootkits(results)

	// Memory protection analysis
	nc.analyzeMemoryProtection(results)

	nc.logger.Info("◢◤ Neural pathway scan complete - %d pathways analyzed", len(rules))
	return nil
}

// readNeuralPathway reads a kernel parameter value
func (nc *NeuralChecker) readNeuralPathway(parameter string) (string, error) {
	// Try /proc/sys first for stealth
	procPath := filepath.Join("/proc/sys", strings.ReplaceAll(parameter, ".", "/"))
	if data, err := os.ReadFile(procPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// Fallback to sysctl if not in stealth mode
	if !nc.stealth {
		output, err := utils.ExecuteCommand("sysctl", "-n", parameter)
		if err != nil {
			return "", fmt.Errorf("neural pathway inaccessible: %w", err)
		}
		return strings.TrimSpace(output), nil
	}

	return "", fmt.Errorf("neural pathway blocked in stealth mode")
}

// getNeuralRules returns comprehensive neural pathway security rules
func (nc *NeuralChecker) getNeuralRules() []NeuralRule {
	return []NeuralRule{
		{
			Parameter:   "net.ipv4.ip_forward",
			Expected:    "0",
			Description: "IP forwarding neural pathway - enables routing exploitation vectors",
			Severity:    SeverityHigh,
			References:  []string{"CIS 3.1.1", "NIST SC-7"},
			Exploitable: true,
			CVEIDs:      []string{"CVE-2019-11477"},
		},
		{
			Parameter:   "net.ipv4.conf.all.send_redirects",
			Expected:    "0",
			Description: "ICMP redirect neural pathway - enables network manipulation attacks",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.1.2"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.default.send_redirects",
			Expected:    "0",
			Description: "Default ICMP redirect neural pathway vulnerability",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.1.3"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.all.accept_source_route",
			Expected:    "0",
			Description: "Source routing neural pathway - critical attack vector",
			Severity:    SeverityHigh,
			References:  []string{"CIS 3.2.1"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.default.accept_source_route",
			Expected:    "0",
			Description: "Default source routing exploitation pathway",
			Severity:    SeverityHigh,
			References:  []string{"CIS 3.2.2"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.icmp_echo_ignore_broadcasts",
			Expected:    "1",
			Description: "ICMP broadcast neural shield - prevents amplification attacks",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.2.5"},
			Exploitable: false,
		},
		{
			Parameter:   "net.ipv4.icmp_ignore_bogus_error_responses",
			Expected:    "1",
			Description: "Bogus ICMP neural filter - blocks malformed packet attacks",
			Severity:    SeverityLow,
			References:  []string{"CIS 3.2.6"},
			Exploitable: false,
		},
		{
			Parameter:   "net.ipv4.conf.all.log_martians",
			Expected:    "1",
			Description: "Martian packet neural logger - detects spoofing attempts",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.2.4"},
			Exploitable: false,
		},
		{
			Parameter:   "net.ipv4.tcp_syncookies",
			Expected:    "1",
			Description: "TCP SYN flood neural protection - prevents DoS attacks",
			Severity:    SeverityHigh,
			References:  []string{"CIS 3.2.8"},
			Exploitable: true,
			CVEIDs:      []string{"CVE-2018-5390"},
		},
		{
			Parameter:   "kernel.randomize_va_space",
			Expected:    "2",
			Description: "ASLR neural scrambler - critical memory protection",
			Severity:    SeverityCritical,
			References:  []string{"CIS 1.5.3"},
			Exploitable: true,
			CVEIDs:      []string{"CVE-2016-3672"},
		},
		{
			Parameter:   "kernel.dmesg_restrict",
			Expected:    "1",
			Description: "Kernel log neural access control - prevents info disclosure",
			Severity:    SeverityMedium,
			References:  []string{"CIS 1.5.1"},
			Exploitable: false,
		},
		{
			Parameter:   "kernel.kptr_restrict",
			Expected:    "2",
			Description: "Kernel pointer neural obfuscation - prevents memory exploits",
			Severity:    SeverityHigh,
			References:  []string{"KSPP"},
			Exploitable: true,
		},
		{
			Parameter:   "kernel.yama.ptrace_scope",
			Expected:    "1",
			Description: "Ptrace neural restriction - prevents process injection",
			Severity:    SeverityHigh,
			References:  []string{"Ubuntu Security"},
			Exploitable: true,
		},
	}
}

// performAdvancedNeuralAnalysis conducts deep neural pathway analysis
func (nc *NeuralChecker) performAdvancedNeuralAnalysis(results *Results) {
	nc.logger.Debug("Performing advanced neural analysis...")

	// Check for kernel compilation flags
	nc.analyzeKernelCompilation(results)

	// Analyze kernel modules
	nc.analyzeLoadedModules(results)

	// Check for kernel debugging interfaces
	nc.checkDebugInterfaces(results)
}

// analyzeKernelCompilation checks kernel compilation security flags
func (nc *NeuralChecker) analyzeKernelCompilation(results *Results) {
	configFile := "/proc/config.gz"
	if !utils.FileExists(configFile) {
		configFile = "/boot/config-" + nc.getKernelVersion()
	}

	if !utils.FileExists(configFile) {
		finding := &Finding{
			ID:          "NEURAL_KERNEL_CONFIG",
			Title:       "Kernel configuration neural pathway inaccessible",
			Description: "Unable to access kernel compilation configuration",
			Severity:    SeverityLow,
			Status:      StatusWarn,
			Expected:    "accessible config",
			Actual:      "config not found",
			Category:    "Neural Pathways",
		}
		results.AddFinding(finding)
		return
	}

	// Check for important security compilation flags
	securityFlags := map[string]string{
		"CONFIG_STRICT_KERNEL_RWX":    "y",
		"CONFIG_STRICT_MODULE_RWX":    "y",
		"CONFIG_RANDOMIZE_BASE":       "y",
		"CONFIG_SLAB_FREELIST_RANDOM": "y",
		"CONFIG_SECURITY":             "y",
	}

	for flag, expected := range securityFlags {
		// This would require actual config parsing implementation
		finding := &Finding{
			ID:          fmt.Sprintf("NEURAL_COMPILE_%s", strings.ReplaceAll(flag, "CONFIG_", "")),
			Title:       fmt.Sprintf("Kernel compilation flag %s", flag),
			Description: fmt.Sprintf("Security compilation flag %s analysis", flag),
			Severity:    SeverityMedium,
			Status:      StatusInfo,
			Expected:    expected,
			Actual:      "requires_analysis",
			Category:    "Neural Pathways",
		}
		results.AddFinding(finding)
	}
}

// analyzeLoadedModules checks for suspicious kernel modules
func (nc *NeuralChecker) analyzeLoadedModules(results *Results) {
	modules, err := utils.ReadLines("/proc/modules")
	if err != nil {
		return
	}

	suspiciousModules := []string{"rootkit", "backdoor", "stealth", "hide"}
	loadedCount := 0

	for _, module := range modules {
		loadedCount++
		fields := strings.Fields(module)
		if len(fields) > 0 {
			moduleName := strings.ToLower(fields[0])
			for _, suspicious := range suspiciousModules {
				if strings.Contains(moduleName, suspicious) {
					finding := &Finding{
						ID:          fmt.Sprintf("NEURAL_SUSPICIOUS_MODULE_%s", strings.ToUpper(fields[0])),
						Title:       fmt.Sprintf("Suspicious neural module detected: %s", fields[0]),
						Description: "Potentially malicious kernel module loaded",
						Severity:    SeverityHigh,
						Status:      StatusFail,
						Expected:    "no suspicious modules",
						Actual:      fmt.Sprintf("module %s loaded", fields[0]),
						Category:    "Neural Pathways",
						Exploitable: true,
					}
					results.AddFinding(finding)
				}
			}
		}
	}

	finding := &Finding{
		ID:          "NEURAL_MODULE_COUNT",
		Title:       fmt.Sprintf("Neural modules loaded: %d", loadedCount),
		Description: "Total number of kernel modules in neural matrix",
		Severity:    SeverityInfo,
		Status:      StatusInfo,
		Expected:    "minimal modules",
		Actual:      fmt.Sprintf("%d modules", loadedCount),
		Category:    "Neural Pathways",
	}
	results.AddFinding(finding)
}

// detectKernelRootkits performs basic rootkit detection
func (nc *NeuralChecker) detectKernelRootkits(results *Results) {
	// Check for common rootkit signatures
	rootkitSigs := []string{
		"/proc/ksyms_memory_disclosure",
		"/proc/kernel_rootkit",
		"/sys/kernel/rootkit",
	}

	for _, sig := range rootkitSigs {
		if utils.FileExists(sig) {
			finding := &Finding{
				ID:          fmt.Sprintf("NEURAL_ROOTKIT_%x", md5.Sum([]byte(sig))),
				Title:       "Kernel rootkit signature detected",
				Description: fmt.Sprintf("Rootkit signature found: %s", sig),
				Severity:    SeverityCritical,
				Status:      StatusFail,
				Expected:    "no rootkit signatures",
				Actual:      fmt.Sprintf("signature: %s", sig),
				Category:    "Neural Pathways",
				Exploitable: true,
			}
			results.AddFinding(finding)
		}
	}
}

// analyzeMemoryProtection checks memory protection mechanisms
func (nc *NeuralChecker) analyzeMemoryProtection(results *Results) {
	// Check if SMEP/SMAP are available
	if cpuinfo, err := utils.ReadLines("/proc/cpuinfo"); err == nil {
		hasSmep := false
		hasSmap := false

		for _, line := range cpuinfo {
			if strings.Contains(line, "flags") || strings.Contains(line, "Features") {
				if strings.Contains(line, "smep") {
					hasSmep = true
				}
				if strings.Contains(line, "smap") {
					hasSmap = true
				}
			}
		}

		finding := &Finding{
			ID:          "NEURAL_MEMORY_PROTECTION",
			Title:       "Hardware memory protection analysis",
			Description: "CPU hardware memory protection features",
			Severity:    SeverityMedium,
			Status:      StatusInfo,
			Expected:    "SMEP+SMAP enabled",
			Actual:      fmt.Sprintf("SMEP: %t, SMAP: %t", hasSmep, hasSmap),
			Category:    "Neural Pathways",
		}
		results.AddFinding(finding)
	}
}

// checkDebugInterfaces checks for kernel debugging interfaces
func (nc *NeuralChecker) checkDebugInterfaces(results *Results) {
	debugPaths := []string{
		"/proc/kcore",
		"/proc/kallsyms",
		"/sys/kernel/debug",
		"/dev/kmem",
		"/dev/mem",
	}

	for _, path := range debugPaths {
		if utils.FileExists(path) {
			info, err := os.Stat(path)
			if err == nil {
				mode := info.Mode()
				accessible := mode&0044 != 0 // world readable

				status := StatusPass
				if accessible {
					status = StatusWarn
				}

				finding := &Finding{
					ID:          fmt.Sprintf("NEURAL_DEBUG_%x", md5.Sum([]byte(path))),
					Title:       fmt.Sprintf("Debug interface: %s", path),
					Description: "Kernel debugging interface accessibility",
					Severity:    SeverityLow,
					Status:      status,
					Expected:    "restricted access",
					Actual:      fmt.Sprintf("mode: %o", mode),
					Category:    "Neural Pathways",
				}
				results.AddFinding(finding)
			}
		}
	}
}

// getKernelVersion returns the current kernel version
func (nc *NeuralChecker) getKernelVersion() string {
	if output, err := utils.ExecuteCommand("uname", "-r"); err == nil {
		return strings.TrimSpace(output)
	}
	return "unknown"
}

// getNeuralRemediation returns remediation for neural pathway issues
func (nc *NeuralChecker) getNeuralRemediation(parameter, expectedValue string) string {
	return fmt.Sprintf(`◢◤ NEURAL PATHWAY REMEDIATION:
┌─ Immediate: sysctl -w %s=%s
├─ Persistent: echo '%s = %s' >> /etc/sysctl.conf  
├─ Apply: sysctl -p /etc/sysctl.conf
└─ Verify: sysctl %s`,
		parameter, expectedValue, parameter, expectedValue, parameter)
}
