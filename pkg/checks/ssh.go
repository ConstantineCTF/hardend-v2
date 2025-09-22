package checks

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ConstantineCTF/hardend/pkg/utils"
)

// GhostChecker handles Ghost Protocol (SSH) security analysis
type GhostChecker struct {
	logger     *utils.CyberpunkLogger
	stealth    bool
	advanced   bool
	configPath string
}

// NewGhostChecker creates a new Ghost Protocol analyzer
func NewGhostChecker(verbose, stealth, advanced bool) *GhostChecker {
	return &GhostChecker{
		logger:     utils.NewCyberpunkLogger(verbose, stealth),
		stealth:    stealth,
		advanced:   advanced,
		configPath: "/etc/ssh/sshd_config",
	}
}

// GhostRule defines a Ghost Protocol security rule
type GhostRule struct {
	Parameter    string
	Expected     string
	Description  string
	Severity     Severity
	References   []string
	ThreatLevel  string
	Exploitable  bool
	AttackVector string
	CVEIDs       []string
}

// RunChecks performs comprehensive Ghost Protocol security analysis
func (gc *GhostChecker) RunChecks(results *Results) error {
	gc.logger.Info("◢◤ Initiating Ghost Protocol analysis...")

	if !gc.stealth {
		utils.ProgressBar("Scanning Ghost Protocol barriers", 1800*time.Millisecond)
	}

	// Check if SSH daemon is accessible
	if !utils.FileExists(gc.configPath) {
		finding := &Finding{
			ID:          "GHOST_CONFIG_MISSING",
			Title:       "Ghost Protocol configuration missing",
			Description: "SSH daemon configuration file not found",
			Severity:    SeverityCritical,
			Status:      StatusFail,
			Expected:    "SSH config present",
			Actual:      "config file missing",
			Category:    "Ghost Protocol",
		}
		results.AddFinding(finding)
		return nil
	}

	// Parse SSH configuration
	config, err := gc.parseGhostConfig()
	if err != nil {
		return fmt.Errorf("failed to parse Ghost Protocol config: %w", err)
	}

	// Analyze Ghost Protocol rules
	rules := gc.getGhostRules()
	for _, rule := range rules {
		gc.logger.Debug("Analyzing Ghost Protocol parameter: %s", rule.Parameter)

		actual := gc.getConfigValue(config, rule.Parameter)
		status := StatusPass
		threat := "SECURED"

		if !gc.validateGhostParameter(rule.Parameter, rule.Expected, actual) {
			status = StatusFail
			threat = rule.ThreatLevel
		}

		finding := &Finding{
			ID:          fmt.Sprintf("GHOST_%s", strings.ToUpper(strings.ReplaceAll(rule.Parameter, " ", "_"))),
			Title:       fmt.Sprintf("Ghost Protocol %s [%s]", rule.Parameter, threat),
			Description: rule.Description,
			Severity:    rule.Severity,
			Status:      status,
			Expected:    rule.Expected,
			Actual:      actual,
			Remediation: gc.getGhostRemediation(rule.Parameter, rule.Expected),
			Category:    "Ghost Protocol",
			References:  rule.References,
			CVEIDs:      rule.CVEIDs,
			Exploitable: rule.Exploitable,
		}
		results.AddFinding(finding)
	}

	// Advanced Ghost Protocol analysis
	if gc.advanced {
		gc.performAdvancedGhostAnalysis(config, results)
	}

	// Analyze SSH keys and authentication
	gc.analyzeSSHKeys(results)

	// Check for SSH backdoors
	gc.detectSSHBackdoors(results)

	gc.logger.Info("◢◤ Ghost Protocol analysis complete")
	return nil
}

// parseGhostConfig parses the SSH daemon configuration
func (gc *GhostChecker) parseGhostConfig() (map[string]string, error) {
	file, err := os.Open(gc.configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			key := strings.ToLower(parts[0])
			value := strings.Join(parts[1:], " ")
			config[key] = value
		}
	}

	return config, scanner.Err()
}

// getConfigValue gets a configuration value with defaults
func (gc *GhostChecker) getConfigValue(config map[string]string, parameter string) string {
	key := strings.ToLower(parameter)
	if value, exists := config[key]; exists {
		return value
	}

	// Return common SSH defaults
	defaults := map[string]string{
		"protocol":                        "2",
		"permitrootlogin":                 "yes",
		"passwordauthentication":          "yes",
		"pubkeyauthentication":            "yes",
		"x11forwarding":                   "yes",
		"maxauthtries":                    "6",
		"clientaliveinterval":             "0",
		"clientalivecountmax":             "3",
		"permitemptypasswords":            "no",
		"challengeresponseauthentication": "yes",
	}

	if defaultVal, exists := defaults[key]; exists {
		return fmt.Sprintf("%s (default)", defaultVal)
	}

	return "not configured"
}

// validateGhostParameter validates a Ghost Protocol parameter
func (gc *GhostChecker) validateGhostParameter(parameter, expected, actual string) bool {
	switch strings.ToLower(parameter) {
	case "maxauthtries":
		expectedNum, _ := strconv.Atoi(expected)
		actualNum, err := strconv.Atoi(strings.Fields(actual)[0])
		if err != nil {
			return false
		}
		return actualNum <= expectedNum
	case "clientaliveinterval":
		expectedNum, _ := strconv.Atoi(expected)
		actualNum, err := strconv.Atoi(strings.Fields(actual)[0])
		if err != nil {
			return false
		}
		return actualNum >= expectedNum && actualNum <= 900
	default:
		return strings.Contains(strings.ToLower(actual), strings.ToLower(expected))
	}
}

// getGhostRules returns comprehensive Ghost Protocol security rules
func (gc *GhostChecker) getGhostRules() []GhostRule {
	return []GhostRule{
		{
			Parameter:    "Protocol",
			Expected:     "2",
			Description:  "SSH Protocol version - legacy v1 has critical vulnerabilities",
			Severity:     SeverityCritical,
			References:   []string{"CIS 5.2.4", "RFC 4253"},
			ThreatLevel:  "CRITICAL_BREACH",
			Exploitable:  true,
			AttackVector: "protocol downgrade attacks, weak encryption",
			CVEIDs:       []string{"CVE-2001-0572", "CVE-1999-1010"},
		},
		{
			Parameter:    "PermitRootLogin",
			Expected:     "no",
			Description:  "Root login via Ghost Protocol - direct admin access vector",
			Severity:     SeverityCritical,
			References:   []string{"CIS 5.2.8", "NIST AC-6"},
			ThreatLevel:  "CRITICAL_BREACH",
			Exploitable:  true,
			AttackVector: "direct root compromise, credential brute-force",
		},
		{
			Parameter:    "PasswordAuthentication",
			Expected:     "no",
			Description:  "Password-based Ghost Protocol auth - brute force vulnerability",
			Severity:     SeverityHigh,
			References:   []string{"CIS 5.2.10"},
			ThreatLevel:  "HIGH_RISK",
			Exploitable:  true,
			AttackVector: "password brute-force, credential stuffing",
		},
		{
			Parameter:    "PubkeyAuthentication",
			Expected:     "yes",
			Description:  "Public key Ghost Protocol authentication - crypto security",
			Severity:     SeverityHigh,
			References:   []string{"CIS 5.2.11"},
			ThreatLevel:  "SECURED",
			Exploitable:  false,
			AttackVector: "strong cryptographic authentication",
		},
		{
			Parameter:    "X11Forwarding",
			Expected:     "no",
			Description:  "X11 forwarding through Ghost Protocol - session hijack risk",
			Severity:     SeverityMedium,
			References:   []string{"CIS 5.2.6"},
			ThreatLevel:  "MEDIUM_RISK",
			Exploitable:  true,
			AttackVector: "X11 session hijacking, keylogger injection",
		},
		{
			Parameter:    "MaxAuthTries",
			Expected:     "3",
			Description:  "Ghost Protocol authentication attempts - brute force mitigation",
			Severity:     SeverityMedium,
			References:   []string{"CIS 5.2.5"},
			ThreatLevel:  "BRUTE_FORCE_PROTECTION",
			Exploitable:  false,
			AttackVector: "automated brute force attacks",
		},
		{
			Parameter:    "ClientAliveInterval",
			Expected:     "300",
			Description:  "Ghost Protocol session timeout - prevents session hijacking",
			Severity:     SeverityLow,
			References:   []string{"CIS 5.2.12"},
			ThreatLevel:  "SESSION_PROTECTION",
			Exploitable:  false,
			AttackVector: "idle session hijacking",
		},
		{
			Parameter:    "PermitEmptyPasswords",
			Expected:     "no",
			Description:  "Empty passwords via Ghost Protocol - authentication bypass",
			Severity:     SeverityCritical,
			References:   []string{"CIS 5.2.9"},
			ThreatLevel:  "CRITICAL_BYPASS",
			Exploitable:  true,
			AttackVector: "authentication bypass, immediate access",
		},
		{
			Parameter:    "ChallengeResponseAuthentication",
			Expected:     "no",
			Description:  "Challenge-response auth - potential bypass vulnerability",
			Severity:     SeverityMedium,
			References:   []string{"CIS 5.2.7"},
			ThreatLevel:  "MEDIUM_RISK",
			Exploitable:  true,
			AttackVector: "authentication method confusion attacks",
		},
		{
			Parameter:    "UsePAM",
			Expected:     "yes",
			Description:  "PAM integration for Ghost Protocol - centralized auth control",
			Severity:     SeverityMedium,
			References:   []string{"Security Best Practice"},
			ThreatLevel:  "AUTH_CONTROL",
			Exploitable:  false,
			AttackVector: "improved authentication controls",
		},
	}
}

// performAdvancedGhostAnalysis conducts deep Ghost Protocol analysis
func (gc *GhostChecker) performAdvancedGhostAnalysis(config map[string]string, results *Results) {
	gc.logger.Debug("Performing advanced Ghost Protocol analysis...")

	// Check for weak ciphers and MACs
	gc.analyzeCryptographicSettings(config, results)

	// Analyze SSH banner and version disclosure
	gc.analyzeVersionDisclosure(results)

	// Check for SSH agent forwarding risks
	gc.analyzeAgentForwarding(config, results)

	// Detect SSH tunneling configurations
	gc.analyzeSSHTunneling(config, results)
}

// analyzeCryptographicSettings checks SSH cryptographic configuration
func (gc *GhostChecker) analyzeCryptographicSettings(config map[string]string, results *Results) {
	// Weak ciphers to avoid
	weakCiphers := []string{"3des", "blowfish", "cast128", "arcfour", "des"}
	weakMACs := []string{"hmac-md5", "hmac-sha1-96", "hmac-md5-96"}

	if ciphers, exists := config["ciphers"]; exists {
		for _, weak := range weakCiphers {
			if strings.Contains(strings.ToLower(ciphers), weak) {
				finding := &Finding{
					ID:          fmt.Sprintf("GHOST_WEAK_CIPHER_%x", md5.Sum([]byte(weak))),
					Title:       fmt.Sprintf("Weak Ghost Protocol cipher: %s", weak),
					Description: "Weak encryption cipher detected in SSH configuration",
					Severity:    SeverityHigh,
					Status:      StatusFail,
					Expected:    "strong ciphers only",
					Actual:      ciphers,
					Category:    "Ghost Protocol",
					Exploitable: true,
				}
				results.AddFinding(finding)
			}
		}
	}

	if macs, exists := config["macs"]; exists {
		for _, weak := range weakMACs {
			if strings.Contains(strings.ToLower(macs), weak) {
				finding := &Finding{
					ID:          fmt.Sprintf("GHOST_WEAK_MAC_%x", md5.Sum([]byte(weak))),
					Title:       fmt.Sprintf("Weak Ghost Protocol MAC: %s", weak),
					Description: "Weak message authentication code in SSH configuration",
					Severity:    SeverityMedium,
					Status:      StatusFail,
					Expected:    "strong MACs only",
					Actual:      macs,
					Category:    "Ghost Protocol",
					Exploitable: true,
				}
				results.AddFinding(finding)
			}
		}
	}
}

// analyzeVersionDisclosure checks for SSH version disclosure
func (gc *GhostChecker) analyzeVersionDisclosure(results *Results) {
	// Try to connect and get SSH banner
	output, err := utils.ExecuteCommand("timeout", "5", "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "localhost", "exit")
	if err == nil || strings.Contains(output, "SSH") {
		if strings.Contains(output, "OpenSSH") {
			// Extract version information
			re := regexp.MustCompile(`OpenSSH_([\d\.]+)`)
			matches := re.FindStringSubmatch(output)
			if len(matches) > 1 {
				version := matches[1]
				finding := &Finding{
					ID:          "GHOST_VERSION_DISCLOSURE",
					Title:       fmt.Sprintf("Ghost Protocol version disclosure: %s", version),
					Description: "SSH version information disclosed in banner",
					Severity:    SeverityLow,
					Status:      StatusInfo,
					Expected:    "minimal version disclosure",
					Actual:      version,
					Category:    "Ghost Protocol",
				}
				results.AddFinding(finding)
			}
		}
	}
}

// analyzeSSHKeys performs SSH key security analysis
func (gc *GhostChecker) analyzeSSHKeys(results *Results) {
	keyPaths := []string{
		"/etc/ssh/ssh_host_rsa_key",
		"/etc/ssh/ssh_host_dsa_key",
		"/etc/ssh/ssh_host_ecdsa_key",
		"/etc/ssh/ssh_host_ed25519_key",
	}

	for _, keyPath := range keyPaths {
		if utils.FileExists(keyPath) {
			gc.analyzeHostKey(keyPath, results)
		}
	}

	// Check for weak host keys
	gc.checkWeakHostKeys(results)
}

// analyzeHostKey analyzes individual SSH host key security
func (gc *GhostChecker) analyzeHostKey(keyPath string, results *Results) {
	info, err := os.Stat(keyPath)
	if err != nil {
		return
	}

	// Check permissions
	mode := info.Mode()
	expectedPerm := os.FileMode(0600)

	status := StatusPass
	if mode != expectedPerm {
		status = StatusFail
	}

	keyType := "unknown"
	if strings.Contains(keyPath, "rsa") {
		keyType = "RSA"
	} else if strings.Contains(keyPath, "dsa") {
		keyType = "DSA"
	} else if strings.Contains(keyPath, "ecdsa") {
		keyType = "ECDSA"
	} else if strings.Contains(keyPath, "ed25519") {
		keyType = "Ed25519"
	}

	severity := SeverityMedium
	if keyType == "DSA" {
		severity = SeverityHigh // DSA keys are considered weak
	}

	finding := &Finding{
		ID:          fmt.Sprintf("GHOST_HOST_KEY_%s", strings.ToUpper(keyType)),
		Title:       fmt.Sprintf("Ghost Protocol %s host key", keyType),
		Description: fmt.Sprintf("SSH %s host key security analysis", keyType),
		Severity:    severity,
		Status:      status,
		Expected:    "0600 permissions",
		Actual:      fmt.Sprintf("%o", mode),
		Category:    "Ghost Protocol",
		Exploitable: keyType == "DSA",
	}
	results.AddFinding(finding)
}

// checkWeakHostKeys checks for weak host key algorithms
func (gc *GhostChecker) checkWeakHostKeys(results *Results) {
	// Check for DSA keys (considered weak)
	if utils.FileExists("/etc/ssh/ssh_host_dsa_key") {
		finding := &Finding{
			ID:          "GHOST_WEAK_DSA_KEY",
			Title:       "Weak DSA host key detected",
			Description: "DSA host keys are cryptographically weak and deprecated",
			Severity:    SeverityHigh,
			Status:      StatusFail,
			Expected:    "RSA, ECDSA, or Ed25519 keys",
			Actual:      "DSA key present",
			Category:    "Ghost Protocol",
			Exploitable: true,
		}
		results.AddFinding(finding)
	}
}

// detectSSHBackdoors checks for SSH-based backdoors
func (gc *GhostChecker) detectSSHBackdoors(results *Results) {
	// Check for suspicious authorized_keys files
	suspiciousPaths := []string{
		"/root/.ssh/authorized_keys",
		"/home/*/.ssh/authorized_keys",
		"/tmp/.ssh/authorized_keys",
		"/var/tmp/.ssh/authorized_keys",
	}

	for _, path := range suspiciousPaths {
		if strings.Contains(path, "*") {
			// This would require glob expansion in real implementation
			continue
		}

		if utils.FileExists(path) {
			content, err := os.ReadFile(path)
			if err == nil {
				lines := strings.Split(string(content), "\n")
				for _, line := range lines {
					if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "#") {
						// Check for suspicious key comments
						if strings.Contains(strings.ToLower(line), "backdoor") ||
							strings.Contains(strings.ToLower(line), "rootkit") ||
							strings.Contains(strings.ToLower(line), "hack") {
							finding := &Finding{
								ID:          fmt.Sprintf("GHOST_BACKDOOR_KEY_%x", md5.Sum([]byte(path))),
								Title:       "Suspicious SSH key detected",
								Description: fmt.Sprintf("Potentially malicious SSH key in %s", path),
								Severity:    SeverityCritical,
								Status:      StatusFail,
								Expected:    "legitimate keys only",
								Actual:      "suspicious key present",
								Category:    "Ghost Protocol",
								Exploitable: true,
							}
							results.AddFinding(finding)
						}
					}
				}
			}
		}
	}
}

// analyzeAgentForwarding checks SSH agent forwarding configuration
func (gc *GhostChecker) analyzeAgentForwarding(config map[string]string, results *Results) {
	if allowAgent, exists := config["allowagentforwarding"]; exists {
		if strings.ToLower(allowAgent) == "yes" {
			finding := &Finding{
				ID:          "GHOST_AGENT_FORWARDING",
				Title:       "SSH agent forwarding enabled",
				Description: "SSH agent forwarding can expose private keys",
				Severity:    SeverityMedium,
				Status:      StatusWarn,
				Expected:    "no (disabled)",
				Actual:      allowAgent,
				Category:    "Ghost Protocol",
				Exploitable: true,
			}
			results.AddFinding(finding)
		}
	}
}

// analyzeSSHTunneling checks for SSH tunneling configuration
func (gc *GhostChecker) analyzeSSHTunneling(config map[string]string, results *Results) {
	tunnelingParams := map[string]string{
		"allowtcpforwarding": "Local/remote port forwarding",
		"gatewayports":       "Gateway port binding",
		"permittunnel":       "Tunnel device forwarding",
	}

	for param, description := range tunnelingParams {
		if value, exists := config[param]; exists {
			if strings.ToLower(value) == "yes" {
				finding := &Finding{
					ID:          fmt.Sprintf("GHOST_TUNNEL_%s", strings.ToUpper(param)),
					Title:       fmt.Sprintf("SSH tunneling enabled: %s", param),
					Description: fmt.Sprintf("%s is enabled - potential data exfiltration vector", description),
					Severity:    SeverityMedium,
					Status:      StatusWarn,
					Expected:    "disabled if not required",
					Actual:      value,
					Category:    "Ghost Protocol",
					Exploitable: true,
				}
				results.AddFinding(finding)
			}
		}
	}
}

// getGhostRemediation returns remediation for Ghost Protocol issues
func (gc *GhostChecker) getGhostRemediation(parameter, expected string) string {
	return fmt.Sprintf(`◢◤ GHOST PROTOCOL REMEDIATION:
┌─ Edit config: sudo nano /etc/ssh/sshd_config
├─ Set parameter: %s %s
├─ Test config: sudo sshd -t
├─ Reload: sudo systemctl reload sshd
└─ Verify: sudo sshd -T | grep -i %s`,
		parameter, expected, strings.ToLower(parameter))
}
