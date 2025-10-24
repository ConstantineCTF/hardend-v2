package checks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ConstantineCTF/hardend/pkg/utils" // Ensure this import path is correct
)

// KernelChecker handles kernel parameter security analysis
type KernelChecker struct {
	logger   *utils.Logger // Corrected: Use Logger
	stealth  bool
	advanced bool // Flag to potentially show more details or INFO checks
}

// NewKernelChecker creates a new kernel parameter analyzer
func NewKernelChecker(verbose, stealth, advanced bool) *KernelChecker {
	return &KernelChecker{
		logger:   utils.NewLogger(verbose, stealth), // Corrected: Use NewLogger
		stealth:  stealth,
		advanced: advanced,
	}
}

// KernelRule defines a kernel parameter security rule
type KernelRule struct {
	Parameter   string
	Expected    string
	Description string
	Severity    Severity
	References  []string
	Exploitable bool
	CVEIDs      []string
}

// RunChecks performs comprehensive kernel parameter analysis
func (kc *KernelChecker) RunChecks(results *Results) error {
	kc.logger.Info("Initiating kernel parameter scan...")

	rules := kc.getKernelRules() // TODO: Load rules from config
	for _, rule := range rules {
		kc.logger.Debug("Scanning kernel parameter: %s", rule.Parameter)

		actual, err := kc.readKernelParameter(rule.Parameter)
		if err != nil {
			// Log error only if verbose, as failure might be expected (e.g., param not present)
			kc.logger.Debug("Could not read kernel parameter %s: %v", rule.Parameter, err)
			// Add finding only if parameter is considered mandatory or critical
			// For now, let's skip adding a finding for read errors unless it's critical
			// You might want specific logic based on the rule severity here.
			continue // Skip this rule if parameter can't be read
		}

		status := StatusPass
		if actual != rule.Expected {
			status = StatusFail
		}

		// Only add findings for non-passing statuses, or if 'advanced' flag is set (to show passing checks)
		if status != StatusPass || kc.advanced {
			finding := &Finding{
				ID:          fmt.Sprintf("KERNEL_%s", strings.ToUpper(strings.ReplaceAll(rule.Parameter, ".", "_"))),
				Title:       fmt.Sprintf("Kernel parameter %s check", rule.Parameter), // Adjusted title
				Description: rule.Description,
				Severity:    rule.Severity,
				Status:      status,
				Expected:    rule.Expected,
				Actual:      actual,
				Remediation: kc.getKernelRemediation(rule.Parameter, rule.Expected),
				Category:    "Kernel Parameters",
				References:  rule.References,
				CVEIDs:      rule.CVEIDs,
				Exploitable: rule.Exploitable,
			}
			// If status is PASS but we're showing it (advanced), adjust severity/status
			if status == StatusPass {
				finding.Severity = SeverityInfo
				finding.Status = StatusInfo // Report as Info if it passed but is shown
				finding.Title = fmt.Sprintf("Kernel parameter %s compliant", rule.Parameter)
			} else {
				finding.Title = fmt.Sprintf("Kernel parameter %s non-compliant", rule.Parameter)
			}
			results.AddFinding(finding)
		}
	}

	kc.logger.Info("Kernel parameter scan complete. %d rules analyzed.", len(rules))
	return nil
}

// readKernelParameter reads a kernel parameter value using /proc/sys or sysctl
func (kc *KernelChecker) readKernelParameter(parameter string) (string, error) {
	// Prefer /proc/sys as it's often faster and requires fewer privileges potentially
	procPath := filepath.Join("/proc/sys", strings.ReplaceAll(parameter, ".", "/"))
	if data, err := os.ReadFile(procPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	} else if !os.IsNotExist(err) {
		// Log unexpected file read error if verbose
		kc.logger.Debug("Error reading %s: %v", procPath, err)
	}

	// Fallback to sysctl if /proc fails or in non-stealth mode
	if !kc.stealth {
		// Use -e flag to ignore errors for non-existent parameters gracefully
		output, err := utils.ExecuteCommand("sysctl", "-n", "-e", parameter)
		if err != nil {
			// If sysctl command fails itself (not just param not found)
			kc.logger.Debug("Sysctl command failed for %s: %v", parameter, err)
			return "", fmt.Errorf("sysctl command failed: %w", err)
		}
		// If parameter doesn't exist, sysctl -e returns empty string, no error
		if output == "" {
			return "", fmt.Errorf("parameter not found via sysctl")
		}
		return strings.TrimSpace(output), nil
	}

	// If in stealth and /proc failed, return error
	return "", fmt.Errorf("parameter inaccessible via /proc/sys in stealth mode")
}

// getKernelRules returns comprehensive kernel parameter security rules
// TODO: Load this from config.go
func (kc *KernelChecker) getKernelRules() []KernelRule {
	// Using professional descriptions
	return []KernelRule{
		{
			Parameter:   "net.ipv4.ip_forward",
			Expected:    "0",
			Description: "IP forwarding allows the host to act as a router. Disable unless required.",
			Severity:    SeverityHigh,
			References:  []string{"CIS 3.1.1"},
			Exploitable: true, // Enabling can lead to MitM if misconfigured
		},
		{
			Parameter:   "net.ipv4.conf.all.send_redirects",
			Expected:    "0",
			Description: "Sending ICMP redirects can be abused for network attacks. Should be disabled.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.1.2"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.default.send_redirects", // Also check default
			Expected:    "0",
			Description: "Default setting for sending ICMP redirects should be disabled.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.1.2"}, // Same reference usually
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.all.accept_source_route",
			Expected:    "0",
			Description: "Accepting source-routed packets is a security risk and should be disabled.",
			Severity:    SeverityHigh,
			References:  []string{"CIS 3.2.1"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.default.accept_source_route", // Also check default
			Expected:    "0",
			Description: "Default setting for accepting source-routed packets should be disabled.",
			Severity:    SeverityHigh,
			References:  []string{"CIS 3.2.1"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.all.accept_redirects", // Accepting redirects
			Expected:    "0",
			Description: "Accepting ICMP redirects can lead to MitM attacks. Should be disabled on non-routers.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.2.3"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.default.accept_redirects", // Default for accepting
			Expected:    "0",
			Description: "Default setting for accepting ICMP redirects should be disabled.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.2.3"},
			Exploitable: true,
		},
		{
			Parameter:   "net.ipv4.conf.all.log_martians",
			Expected:    "1",
			Description: "Logging packets with impossible source addresses (martians) helps detect spoofing.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 3.2.4"},
			Exploitable: false, // Logging itself isn't exploitable if disabled
		},
		{
			Parameter:   "net.ipv4.tcp_syncookies",
			Expected:    "1",
			Description: "TCP SYN cookies help protect against SYN flood DoS attacks.",
			Severity:    SeverityHigh,
			References:  []string{"CIS 3.2.8"},
			Exploitable: true, // Disabling makes system vulnerable to SYN floods
		},
		{
			Parameter:   "kernel.randomize_va_space",
			Expected:    "2",
			Description: "Address Space Layout Randomization (ASLR) makes buffer overflow exploits harder. Should be set to 2 (full randomization).",
			Severity:    SeverityCritical,
			References:  []string{"CIS 1.5.3"},
			Exploitable: true, // Disabling makes exploits easier
		},
		{
			Parameter:   "kernel.dmesg_restrict",
			Expected:    "1",
			Description: "Restricting non-root access to kernel logs (dmesg) prevents information leakage.",
			Severity:    SeverityLow, // Often considered low/medium
			References:  []string{"CIS 1.5.1"},
			Exploitable: false, // Info leak, not direct exploit usually
		},
		{
			Parameter:   "kernel.kptr_restrict",
			Expected:    "2", // Setting 1 hides from non-cap users, 2 hides always unless cap_syslog
			Description: "Restricting exposure of kernel pointer addresses via /proc prevents information leakage useful for exploits.",
			Severity:    SeverityMedium, // Often considered medium/high
			References:  []string{"Kernel Hardening Best Practice"},
			Exploitable: false, // Info leak, aids exploitation
		},
		{
			Parameter:   "fs.suid_dumpable", // Controls coredumps for SUID binaries
			Expected:    "0",
			Description: "Prevent core dumps of SUID/SGID processes to avoid leaking sensitive memory contents.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 1.5.4"},
			Exploitable: false, // Info leak
		},
		// Example rule for a parameter that might not exist on all kernels
		// {
		// 	Parameter:   "kernel.yama.ptrace_scope",
		// 	Expected:    "1", // Or higher (2, 3 depending on policy)
		// 	Description: "Restricting ptrace scope limits process debugging/injection capabilities.",
		// 	Severity:    SeverityHigh,
		// 	References:  []string{"Yama Security Module"},
		// 	Exploitable: true, // Allows process injection if set to 0
		// },
	}
}

// getKernelRemediation returns remediation for kernel parameter issues
func (kc *KernelChecker) getKernelRemediation(parameter, expectedValue string) string {
	// Standard sysctl remediation instructions
	return fmt.Sprintf(
		"To apply immediately: 'sudo sysctl -w %s=%s'.\nTo make persistent: Add '%s = %s' to '/etc/sysctl.conf' or a file in '/etc/sysctl.d/' and run 'sudo sysctl -p'.",
		parameter, expectedValue, parameter, expectedValue)
}
