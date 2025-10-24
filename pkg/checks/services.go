package checks

import (
	"fmt"
	"strings"

	"github.com/ConstantineCTF/hardend/pkg/utils" // Ensure this import path is correct
)

// ServicesChecker handles service security analysis
type ServicesChecker struct {
	logger   *utils.Logger // Corrected: Use Logger
	stealth  bool
	advanced bool // Flag to potentially show more details or INFO checks
}

// NewServicesChecker creates a new service analyzer
func NewServicesChecker(verbose, stealth, advanced bool) *ServicesChecker {
	return &ServicesChecker{
		logger:   utils.NewLogger(verbose, stealth), // Corrected: Use NewLogger
		stealth:  stealth,
		advanced: advanced,
	}
}

// ServiceRule defines a service security rule
type ServiceRule struct {
	ServiceName  string
	ShouldRun    bool // True if required, False if prohibited
	Description  string
	Severity     Severity
	References   []string
	Exploitable  bool
	AttackVector string // Optional: Describe attack if prohibited service is running
}

// RunChecks performs comprehensive service analysis
func (sc *ServicesChecker) RunChecks(results *Results) error {
	sc.logger.Info("Initiating service scan...")

	rules := sc.getServiceRules() // TODO: Load rules from config
	for _, rule := range rules {
		sc.logger.Debug("Scanning service: %s", rule.ServiceName)

		isRunning, isEnabled, err := sc.analyzeServiceStatus(rule.ServiceName)
		// Error handling: Log if verbose, decide whether to add a finding
		if err != nil {
			sc.logger.Debug("Could not determine status for service %s: %v", rule.ServiceName, err)
			// Optionally add a finding if status check fails for a critical service
			if rule.ShouldRun && rule.Severity >= SeverityHigh {
				finding := &Finding{
					ID:          fmt.Sprintf("SVC_%s_ERROR", strings.ToUpper(rule.ServiceName)),
					Title:       fmt.Sprintf("Service %s status check failed", rule.ServiceName),
					Description: fmt.Sprintf("Unable to determine status for required service %s: %v", rule.ServiceName, err),
					Severity:    SeverityMedium, // Downgrade slightly as it's an error, not confirmed state
					Status:      StatusSkip,
					Expected:    fmt.Sprintf("should_run: %t", rule.ShouldRun),
					Actual:      fmt.Sprintf("Check Error: %v", err),
					Category:    "Services",
					References:  rule.References,
				}
				results.AddFinding(finding)
			}
			continue // Skip rule if status cannot be determined
		}

		status := StatusPass
		pass := true

		if rule.ShouldRun {
			// Rule: Service SHOULD be running AND enabled
			if !isRunning || !isEnabled {
				status = StatusFail
				pass = false
			}
		} else {
			// Rule: Service should NOT be running AND NOT enabled
			if isRunning || isEnabled {
				status = StatusFail
				pass = false
			}
		}

		// Add finding if failed, or if passed and advanced/verbose mode is on
		if !pass || sc.advanced {
			finding := &Finding{
				ID:          fmt.Sprintf("SVC_%s", strings.ToUpper(rule.ServiceName)),
				Title:       fmt.Sprintf("Service %s status check", rule.ServiceName),
				Description: rule.Description,
				Severity:    rule.Severity,
				Status:      status,
				Expected:    fmt.Sprintf("running=%t, enabled=%t", rule.ShouldRun, rule.ShouldRun),
				Actual:      fmt.Sprintf("running=%t, enabled=%t", isRunning, isEnabled),
				Remediation: sc.getServiceRemediation(rule.ServiceName, rule.ShouldRun),
				Category:    "Services",
				References:  rule.References,
				Exploitable: rule.Exploitable && !pass, // Only exploitable if the check failed
			}
			if pass { // If showing passed check in advanced mode
				finding.Severity = SeverityInfo
				finding.Status = StatusInfo
				finding.Title = fmt.Sprintf("Service %s status compliant", rule.ServiceName)
			} else {
				finding.Title = fmt.Sprintf("Service %s status non-compliant", rule.ServiceName)
			}
			results.AddFinding(finding)
		}
	}

	sc.logger.Info("Service scan complete. %d rules analyzed.", len(rules))
	return nil
}

// analyzeServiceStatus checks the status of a service using systemctl or pgrep
func (sc *ServicesChecker) analyzeServiceStatus(serviceName string) (isRunning bool, isEnabled bool, err error) {
	if sc.stealth {
		// Stealth mode: use pgrep (only checks if running)
		// Note: This is less reliable as process name might differ from service name
		isRunning = utils.CheckProcessRunning(serviceName)
		// We cannot reliably check 'enabled' status in stealth mode easily. Assume based on running status.
		isEnabled = isRunning
		return isRunning, isEnabled, nil // No error returned from CheckProcessRunning in this impl
	}

	// Normal mode: use systemctl
	activeOutput, activeErr := utils.ExecuteCommand("systemctl", "is-active", serviceName)
	if activeErr != nil {
		// Error might mean service doesn't exist or systemctl failed. Log if verbose.
		sc.logger.Debug("systemctl is-active failed for %s: %v (Output: %s)", serviceName, activeErr, activeOutput)
		// If error is 'exit status 3', it means inactive, not necessarily an error running the command.
		// Other errors might be more serious. We'll treat any error as 'not running'.
	}
	isRunning = activeErr == nil && strings.TrimSpace(activeOutput) == "active"

	enabledOutput, enabledErr := utils.ExecuteCommand("systemctl", "is-enabled", serviceName)
	if enabledErr != nil {
		// Error might mean service doesn't exist or systemctl failed.
		sc.logger.Debug("systemctl is-enabled failed for %s: %v (Output: %s)", serviceName, enabledErr, enabledOutput)
		// If error is 'exit status 1', it usually means disabled/static etc. Treat as not enabled.
	}
	// Note: 'static' services are also considered not 'enabled' in the traditional sense.
	isEnabled = enabledErr == nil && strings.TrimSpace(enabledOutput) == "enabled"

	// Decide if we should return an error to the caller
	// For now, let's assume if systemctl ran but service not found, it's not an *execution* error
	// but rather the service state is determined. Return nil error unless systemctl itself failed badly.
	if activeErr != nil && !strings.Contains(activeErr.Error(), "exit status") {
		return false, false, activeErr // Return error if systemctl command likely failed
	}
	if enabledErr != nil && !strings.Contains(enabledErr.Error(), "exit status") {
		return isRunning, false, enabledErr // Return error if systemctl command likely failed
	}

	return isRunning, isEnabled, nil // No execution error
}

// getServiceRules returns comprehensive service security rules
// TODO: Load this from config.yaml
func (sc *ServicesChecker) getServiceRules() []ServiceRule {
	// Professional rules based on common hardening guides
	return []ServiceRule{
		// --- Prohibited Services (ShouldRun: false) ---
		{
			ServiceName:  "telnet.socket", // Often socket-activated
			ShouldRun:    false,
			Description:  "Telnet is an unencrypted remote access protocol.",
			Severity:     SeverityCritical,
			References:   []string{"CIS 2.1.1"},
			Exploitable:  true,
			AttackVector: "Plaintext credential sniffing, Man-in-the-Middle.",
		},
		{
			ServiceName:  "rsh.socket",
			ShouldRun:    false,
			Description:  "Remote Shell (rsh) is an insecure legacy protocol using weak authentication.",
			Severity:     SeverityCritical,
			References:   []string{"CIS 2.1.2"},
			Exploitable:  true,
			AttackVector: "Authentication bypass, remote command execution.",
		},
		{
			ServiceName: "rlogin.socket",
			ShouldRun:   false,
			Description: "Remote Login (rlogin) is an insecure legacy protocol.",
			Severity:    SeverityCritical,
			References:  []string{"CIS 2.1.3"},
			Exploitable: true,
		},
		{
			ServiceName: "ypbind", // NIS/YP client service
			ShouldRun:   false,
			Description: "Network Information Service (NIS/YP) is an insecure legacy directory service.",
			Severity:    SeverityHigh,
			References:  []string{"CIS 2.1.5"},
			Exploitable: true, // Can leak user/password info
		},
		{
			ServiceName: "avahi-daemon",
			ShouldRun:   false,
			Description: "Avahi (mDNS/DNS-SD) broadcasts network services, potentially leaking information on non-essential systems.",
			Severity:    SeverityLow,
			References:  []string{"CIS 2.2.3"},
			Exploitable: false, // Information leak
		},
		{
			ServiceName: "cups", // CUPS printing service
			ShouldRun:   false,
			Description: "CUPS printing service increases attack surface. Disable on systems not requiring printing.",
			Severity:    SeverityLow,
			References:  []string{"CIS 2.2.4"},
			Exploitable: false, // Can have vulnerabilities, but disabling is hardening
		},
		{
			ServiceName: "isc-dhcp-server", // Or dhcpd depending on distro
			ShouldRun:   false,
			Description: "DHCP Server service should only run on designated DHCP servers.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 2.2.5"},
			Exploitable: true, // Rogue DHCP server risk
		},
		{
			ServiceName: "slapd", // OpenLDAP server
			ShouldRun:   false,
			Description: "LDAP Server service should only run on designated LDAP servers.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 2.2.6"}, // Example reference
			Exploitable: false,                 // Depends on config if running
		},
		{
			ServiceName: "nfs-server", // Or nfsd
			ShouldRun:   false,
			Description: "NFS Server service should only run on designated NFS servers.",
			Severity:    SeverityMedium,
			References:  []string{"CIS 2.2.7"}, // Example reference
			Exploitable: true,                  // Misconfigured NFS is risky
		},
		{
			ServiceName: "rpcbind", // RPC portmapper, often needed by NFS but risky
			ShouldRun:   false,
			Description: "RPCbind service is often unnecessary and can be exploited. Disable if not required (e.g., by NFS).",
			Severity:    SeverityMedium,
			References:  []string{"CIS 2.2.8"}, // Example reference
			Exploitable: true,
		},
		{
			ServiceName: "vsftpd", // Example FTP server
			ShouldRun:   false,
			Description: "FTP servers transmit credentials and data in plaintext. Use SFTP (via SSH) instead.",
			Severity:    SeverityHigh,
			References:  []string{"Security Best Practice"},
			Exploitable: true,
		},

		// --- Required Services (ShouldRun: true) ---
		{
			ServiceName: "sshd", // Or ssh.service depending on distro naming
			ShouldRun:   true,
			Description: "SSH Daemon (sshd) provides secure, encrypted remote access.",
			Severity:    SeverityHigh, // High severity if NOT running/enabled on a server needing remote access
			References:  []string{"CIS 5.2.1"},
			Exploitable: false, // Not running isn't exploitable, it's an availability issue
		},
		{
			ServiceName: "auditd",
			ShouldRun:   true,
			Description: "Linux Audit Daemon (auditd) is crucial for security logging, monitoring, and forensics.",
			Severity:    SeverityHigh,
			References:  []string{"CIS 4.1.1.1"},
			Exploitable: false, // Lack of logging aids attackers post-compromise
		},
		// Example: Require rsyslog or syslog-ng
		// {
		//     ServiceName: "rsyslog",
		//     ShouldRun:   true,
		//     Description: "System logging daemon (rsyslog) is essential for collecting system and application logs.",
		//     Severity:    SeverityMedium,
		//     References:  []string{"CIS 4.2.1.1"},
		//     Exploitable: false,
		// },
		// Example: Require chrony or ntp
		// {
		//     ServiceName: "chronyd", // Or ntpd
		//     ShouldRun:   true,
		//     Description: "Network Time Protocol daemon (chronyd/ntpd) is essential for accurate time synchronization, important for logs and security protocols.",
		//     Severity:    SeverityMedium,
		//     References:  []string{"CIS 2.2.1.2"},
		//     Exploitable: false, // Inaccurate time can cause issues
		// },
	}
}

// getServiceRemediation returns remediation instructions for service issues
func (sc *ServicesChecker) getServiceRemediation(serviceName string, shouldRun bool) string {
	if shouldRun {
		// Remediation for a required service that is not running/enabled
		return fmt.Sprintf(
			"Service '%s' is required but is inactive or disabled.\nTo fix: Run 'sudo systemctl enable --now %s' to enable and start it.",
			serviceName, serviceName)
	} else {
		// Remediation for a prohibited service that is running/enabled
		return fmt.Sprintf(
			"Service '%s' is prohibited or unnecessary and is active or enabled.\nTo fix: Run 'sudo systemctl disable --now %s' to disable and stop it.",
			serviceName, serviceName)
	}
}
