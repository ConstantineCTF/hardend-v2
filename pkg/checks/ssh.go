package checks

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ConstantineCTF/hardend/pkg/utils" // Ensure this import path is correct
)

// SSHChecker handles SSH security analysis
type SSHChecker struct {
	logger     *utils.Logger // Corrected: Use Logger
	stealth    bool
	configPath string
}

// NewSSHChecker creates a new SSH analyzer
func NewSSHChecker(verbose, stealth bool) *SSHChecker {
	return &SSHChecker{
		logger:     utils.NewLogger(verbose, stealth), // Corrected: Use NewLogger
		stealth:    stealth,
		configPath: "/etc/ssh/sshd_config",
	}
}

// SSHRule defines an SSH security rule
type SSHRule struct {
	Parameter   string
	Expected    string
	Description string
	Severity    Severity
	References  []string
	Exploitable bool
	CVEIDs      []string
}

// RunChecks performs comprehensive SSH security analysis
func (sc *SSHChecker) RunChecks(results *Results) error {
	sc.logger.Info("Initiating SSH security analysis...")

	// ... (file existence check and config parsing remain the same) ...
	// Make sure error handling for parsing uses the logger and returns correctly
	config, err := sc.parseSSHConfig()
	if err != nil {
		sc.logger.Error("Failed to parse SSH config: %v", err)
		finding := &Finding{ // Add a finding about the parse error
			ID:          "SSH_CONFIG_PARSE_ERROR",
			Title:       "Failed to parse SSH configuration",
			Description: fmt.Sprintf("Error parsing %s: %v", sc.configPath, err),
			Severity:    SeverityMedium,
			Status:      StatusSkip,
			Category:    "SSH Security",
		}
		results.AddFinding(finding)
		return fmt.Errorf("failed to parse SSH config: %w", err)
	}

	// Analyze SSH rules
	rules := sc.getSSHRules()
	for _, rule := range rules {
		sc.logger.Debug("Analyzing SSH parameter: %s", rule.Parameter)

		actual := sc.getConfigValue(config, rule.Parameter)
		status := StatusPass
		title := fmt.Sprintf("SSH Parameter '%s' is compliant", rule.Parameter)

		if !sc.validateSSHParameter(rule.Parameter, rule.Expected, actual) {
			status = StatusFail
			title = fmt.Sprintf("SSH Parameter '%s' is non-compliant", rule.Parameter)
		}

		// *** THIS IS THE CORRECTED LINE ***
		// Only add findings for non-passing statuses unless verbose/advanced mode requires it
		if status != StatusPass || sc.logger.IsVerbose() { // Use the IsVerbose() method
			finding := &Finding{
				ID:          fmt.Sprintf("SSH_%s", strings.ToUpper(strings.ReplaceAll(rule.Parameter, " ", "_"))),
				Title:       title,
				Description: rule.Description,
				Severity:    rule.Severity,
				Status:      status,
				Expected:    rule.Expected,
				Actual:      actual,
				Remediation: sc.getSSHRemediation(rule.Parameter, rule.Expected),
				Category:    "SSH Security",
				References:  rule.References,
				CVEIDs:      rule.CVEIDs,
				Exploitable: rule.Exploitable && status == StatusFail, // Exploitable only if it failed
			}
			// If status is PASS but we're showing it (verbose), adjust severity/status
			if status == StatusPass {
				finding.Severity = SeverityInfo
				finding.Status = StatusInfo // Report as Info if it passed but is shown
			}
			results.AddFinding(finding)
		}
	}

	sc.logger.Info("SSH security analysis complete.")
	return nil
}

// parseSSHConfig parses the SSH daemon configuration
func (sc *SSHChecker) parseSSHConfig() (map[string]string, error) {
	file, err := os.Open(sc.configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split line into key and value (handle potential spaces in value)
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.ToLower(parts[0])
			// Join remaining parts as value, preserving spaces
			value := strings.Join(parts[1:], " ")
			config[key] = value
		} else if len(parts) == 1 {
			// Handle parameters with no value (implicitly 'yes' or specific default)
			// Depending on the parameter, you might need specific logic here.
			// For simplicity, we can store it with a placeholder or handle in validation.
			config[strings.ToLower(parts[0])] = "" // Or some indicator like "<no_value>"
		}
	}
	return config, scanner.Err()
}

// getConfigValue gets a configuration value with defaults
func (sc *SSHChecker) getConfigValue(config map[string]string, parameter string) string {
	key := strings.ToLower(parameter)
	if value, exists := config[key]; exists {
		// Handle case where parameter exists but has no explicit value
		if value == "" {
			// Return a specific default based on the parameter if needed, e.g.,
			// if key == "someflag" { return "yes" }
			return "<present_no_value>" // Indicate it was present but empty
		}
		return value
	}

	// Return common SSH defaults only if the parameter wasn't found at all
	defaults := map[string]string{
		"protocol":                        "2",
		"permitrootlogin":                 "prohibit-password", // More secure default often used now
		"passwordauthentication":          "yes",
		"pubkeyauthentication":            "yes",
		"x11forwarding":                   "no", // More secure default
		"maxauthtries":                    "6",
		"clientaliveinterval":             "0",
		"clientalivecountmax":             "3",
		"permitemptypasswords":            "no",
		"challengeresponseauthentication": "no", // Often disabled now
		"usepam":                          "yes",
	}

	if defaultVal, exists := defaults[key]; exists {
		return fmt.Sprintf("%s (default)", defaultVal)
	}
	return "not configured"
}

// validateSSHParameter validates an SSH parameter
func (sc *SSHChecker) validateSSHParameter(parameter, expected, actual string) bool {
	// Handle "(default)" suffix if present
	actualValue := strings.TrimSuffix(actual, " (default)")
	// Handle parameters present without value
	if actualValue == "<present_no_value>" {
		// Decide validation based on parameter, e.g., treat as 'yes' or fail
		// For simplicity, let's treat it as not matching unless expected is also empty/special
		return expected == "" || expected == "<present_no_value>"
	}

	key := strings.ToLower(parameter)

	switch key {
	case "maxauthtries":
		expectedNum, errExpected := strconv.Atoi(expected)
		actualNum, errActual := strconv.Atoi(actualValue)
		// Check for conversion errors and then compare
		return errExpected == nil && errActual == nil && actualNum <= expectedNum
	case "clientaliveinterval":
		expectedNum, errExpected := strconv.Atoi(expected)
		actualNum, errActual := strconv.Atoi(actualValue)
		// Check range (e.g., 300 to 900 seconds is reasonable)
		return errExpected == nil && errActual == nil && actualNum >= expectedNum && actualNum <= 900
	case "protocol":
		// Ensure ONLY protocol 2 is specified
		return strings.TrimSpace(actualValue) == "2"
	case "permitrootlogin", "passwordauthentication", "pubkeyauthentication",
		"x11forwarding", "permitemptypasswords", "challengeresponseauthentication", "usepam":
		// Simple case-insensitive comparison for yes/no/prohibit-password etc.
		return strings.ToLower(actualValue) == strings.ToLower(expected)
	default:
		// Default to exact match if no specific logic
		return actualValue == expected
	}
}

// getSSHRules returns comprehensive SSH security rules
// TODO: Load this from config.yaml for better flexibility
func (sc *SSHChecker) getSSHRules() []SSHRule {
	// Using more up-to-date recommendations where applicable
	return []SSHRule{
		{
			Parameter:   "Protocol",
			Expected:    "2",
			Description: "SSH Protocol version 1 has critical vulnerabilities and should be disabled. Only Protocol 2 should be used.",
			Severity:    SeverityCritical,
			References:  []string{"CIS Benchmark", "RFC 4253"},
			Exploitable: true,
		},
		{
			Parameter:   "PermitRootLogin",
			Expected:    "no", // Or "prohibit-password"
			Description: "Disabling direct root login via SSH mitigates brute-force attacks against the root account.",
			Severity:    SeverityCritical,
			References:  []string{"CIS Benchmark"},
			Exploitable: true,
		},
		{
			Parameter:   "PasswordAuthentication",
			Expected:    "no",
			Description: "Password-based authentication is vulnerable to brute-force attacks. Key-based authentication is strongly recommended.",
			Severity:    SeverityHigh,
			References:  []string{"CIS Benchmark"},
			Exploitable: true,
		},
		{
			Parameter:   "PubkeyAuthentication",
			Expected:    "yes",
			Description: "Public key authentication should be enabled as the preferred secure method.",
			Severity:    SeverityMedium, // Medium because if disabled, likely using passwords (covered above)
			References:  []string{"Security Best Practice"},
			Exploitable: false, // Disabling it isn't exploitable itself, but encourages weaker methods
		},
		{
			Parameter:   "X11Forwarding",
			Expected:    "no",
			Description: "X11 forwarding can create security vulnerabilities (e.g., session hijacking, keystroke injection) and should be disabled unless specifically required.",
			Severity:    SeverityMedium,
			References:  []string{"CIS Benchmark"},
			Exploitable: true,
		},
		{
			Parameter:   "MaxAuthTries",
			Expected:    "3", // Reduced from 6 for better brute-force mitigation
			Description: "Limit the number of authentication attempts per connection to mitigate brute-force attacks.",
			Severity:    SeverityMedium,
			References:  []string{"CIS Benchmark"},
			Exploitable: false,
		},
		{
			Parameter:   "ClientAliveInterval",
			Expected:    "300", // e.g., 5 minutes
			Description: "Set a timeout interval for idle client connections to prevent session hijacking.",
			Severity:    SeverityLow,
			References:  []string{"CIS Benchmark"},
			Exploitable: false,
		},
		{
			Parameter:   "ClientAliveCountMax",
			Expected:    "0", // Setting CountMax to 0 means connection drops after Interval timeout
			Description: "Set the number of client alive messages before disconnecting. 0 drops connection immediately after interval.",
			Severity:    SeverityLow,
			References:  []string{"CIS Benchmark"},
			Exploitable: false,
		},
		{
			Parameter:   "PermitEmptyPasswords",
			Expected:    "no",
			Description: "Disallow authentication with empty passwords.",
			Severity:    SeverityCritical,
			References:  []string{"CIS Benchmark"},
			Exploitable: true,
		},
		{
			Parameter:   "ChallengeResponseAuthentication",
			Expected:    "no",
			Description: "Challenge-Response authentication is often unnecessary and can sometimes be leveraged in attacks. Disable unless required for specific PAM modules.",
			Severity:    SeverityMedium,
			References:  []string{"CIS Benchmark"},
			Exploitable: false, // Disabling it isn't exploitable, enabling it might be depending on PAM
		},
		{
			Parameter:   "UsePAM",
			Expected:    "yes",
			Description: "Enable Pluggable Authentication Modules (PAM) for centralized authentication control and policies.",
			Severity:    SeverityMedium,
			References:  []string{"Security Best Practice"},
			Exploitable: false,
		},
		{
			Parameter:   "IgnoreRhosts", // Deprecated but good to check
			Expected:    "yes",
			Description: "Ensure legacy Rhosts-based authentication is ignored.",
			Severity:    SeverityHigh,
			References:  []string{"CIS Benchmark"},
			Exploitable: true, // If not ignored, .rhosts files could allow auth bypass
		},
		{
			Parameter:   "HostbasedAuthentication", // Generally less common, disable unless needed
			Expected:    "no",
			Description: "Host-based authentication relies on client host verification and can be complex to secure properly.",
			Severity:    SeverityMedium,
			References:  []string{"CIS Benchmark"},
			Exploitable: false,
		},
		// Add checks for Ciphers, MACs, KexAlgorithms here later if desired
	}
}

// getSSHRemediation returns remediation for SSH issues
func (sc *SSHChecker) getSSHRemediation(parameter, expected string) string {
	// Provide slightly more robust restart command example
	return fmt.Sprintf(
		"Edit '%s', set '%s %s', save the file, then test configuration with 'sudo sshd -t' and restart the service ('sudo systemctl restart sshd' or 'sudo service ssh restart').",
		sc.configPath, parameter, expected)
}
