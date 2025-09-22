package checks

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ConstantineCTF/hardend/pkg/utils"
	"github.com/fatih/color"
)

// MatrixChecker handles Filesystem Matrix security analysis
type MatrixChecker struct {
	logger   *utils.CyberpunkLogger
	stealth  bool
	advanced bool
}

// NewMatrixChecker creates a new Filesystem Matrix analyzer
func NewMatrixChecker(verbose, stealth, advanced bool) *MatrixChecker {
	return &MatrixChecker{
		logger:   utils.NewCyberpunkLogger(verbose, stealth),
		stealth:  stealth,
		advanced: advanced,
	}
}

// MatrixMountInfo represents enhanced mount information
type MatrixMountInfo struct {
	Device     string
	MountPoint string
	FSType     string
	Options    []string
	Flags      uintptr
}

// RunChecks performs comprehensive Filesystem Matrix security analysis
func (mc *MatrixChecker) RunChecks(results *Results) error {
	mc.logger.Info("◢◤ Initiating Filesystem Matrix scan...")

	if !mc.stealth {
		utils.ProgressBar("Analyzing filesystem matrix structure", 2*time.Second)
	}

	// Scan for dangerous filesystem modules
	mc.scanDangerousFilesystems(results)

	// Analyze mount point security
	mc.analyzeMountSecurity(results)

	// Check partition layout
	mc.analyzePartitionLayout(results)

	// Advanced matrix analysis
	if mc.advanced {
		mc.performAdvancedMatrixAnalysis(results)
	}

	// Scan for hidden filesystems and rootkits
	mc.scanHiddenFilesystems(results)

	// Check filesystem quotas and limits
	mc.analyzeFilesystemLimits(results)

	mc.logger.Info("◢◤ Filesystem Matrix scan complete")
	return nil
}

// scanDangerousFilesystems checks for dangerous filesystem types
func (mc *MatrixChecker) scanDangerousFilesystems(results *Results) {
	dangerousFS := map[string]string{
		"cramfs":   "compressed ROM filesystem - potential code injection",
		"freevxfs": "Veritas filesystem - proprietary, limited security controls",
		"jffs2":    "Journaling Flash filesystem - embedded system vulnerabilities",
		"hfs":      "Apple HFS - case sensitivity bypass vulnerabilities",
		"hfsplus":  "Apple HFS+ - extended attribute manipulation",
		"udf":      "Universal Disk Format - buffer overflow vulnerabilities",
		"squashfs": "compressed read-only filesystem - if writable, compromised",
		"ntfs":     "Windows NTFS - ACL bypass on Linux systems",
		"fat32":    "FAT32 - no permission controls, privilege escalation risk",
	}

	for fsType, threat := range dangerousFS {
		loaded := mc.isFilesystemLoaded(fsType)
		available := mc.isFilesystemAvailable(fsType)

		status := StatusPass
		severity := SeverityMedium
		exploitable := false

		if loaded {
			status = StatusFail
			severity = SeverityHigh
			exploitable = true
		} else if available {
			status = StatusWarn
			severity = SeverityLow
		}

		finding := &Finding{
			ID: fmt.Sprintf("MATRIX_FS_%s", strings.ToUpper(fsType)),
			Title: fmt.Sprintf("Dangerous filesystem %s [%s]", fsType,
				map[bool]string{true: "LOADED", false: map[bool]string{true: "AVAILABLE", false: "SECURE"}[available]}[loaded]),
			Description: threat,
			Severity:    severity,
			Status:      status,
			Expected:    "not loaded/disabled",
			Actual:      fmt.Sprintf("loaded: %t, available: %t", loaded, available),
			Remediation: mc.getFilesystemRemediation(fsType),
			Category:    "Filesystem Matrix",
			Exploitable: exploitable,
		}
		results.AddFinding(finding)
	}
}

// analyzeMountSecurity performs comprehensive mount point security analysis
func (mc *MatrixChecker) analyzeMountSecurity(results *Results) {
	mounts, err := mc.getMatrixMountInfo()
	if err != nil {
		mc.logger.Error("Failed to read filesystem matrix: %v", err)
		return
	}

	// Critical mount points and their required security options
	criticalMounts := map[string][]string{
		"/tmp":     {"nosuid", "noexec", "nodev"},
		"/var/tmp": {"nosuid", "noexec", "nodev"},
		"/dev/shm": {"nosuid", "noexec", "nodev"},
		"/home":    {"nosuid", "nodev"},
		"/var":     {"nosuid", "nodev"},
		"/usr":     {"nodev"},
		"/boot":    {"nosuid", "noexec", "nodev"},
	}

	mountMap := make(map[string]MatrixMountInfo)
	for _, mount := range mounts {
		mountMap[mount.MountPoint] = mount
	}

	for mountPoint, requiredOpts := range criticalMounts {
		if mount, exists := mountMap[mountPoint]; exists {
			for _, requiredOpt := range requiredOpts {
				hasOption := mc.hasMountOption(mount.Options, requiredOpt)

				status := StatusPass
				severity := SeverityMedium
				exploitable := false

				if !hasOption {
					status = StatusFail
					exploitable = true
					if requiredOpt == "noexec" || requiredOpt == "nosuid" {
						severity = SeverityHigh
					}
				}

				finding := &Finding{
					ID: fmt.Sprintf("MATRIX_MOUNT_%s_%s",
						strings.ToUpper(strings.ReplaceAll(mountPoint, "/", "_")),
						strings.ToUpper(requiredOpt)),
					Title: fmt.Sprintf("Mount %s %s option [%s]", mountPoint, requiredOpt,
						map[bool]string{true: "SECURED", false: "VULNERABLE"}[hasOption]),
					Description: fmt.Sprintf("Security mount option %s for %s", requiredOpt, mountPoint),
					Severity:    severity,
					Status:      status,
					Expected:    requiredOpt + " enabled",
					Actual:      strings.Join(mount.Options, ","),
					Remediation: mc.getMountRemediation(mountPoint, requiredOpt),
					Category:    "Filesystem Matrix",
					Exploitable: exploitable,
				}
				results.AddFinding(finding)
			}
		} else {
			// Mount point not found as separate partition
			finding := &Finding{
				ID:          fmt.Sprintf("MATRIX_SEPARATE_%s", strings.ToUpper(strings.ReplaceAll(mountPoint, "/", "_"))),
				Title:       fmt.Sprintf("Separate partition %s [MISSING]", mountPoint),
				Description: fmt.Sprintf("%s should be on a separate partition for security isolation", mountPoint),
				Severity:    SeverityMedium,
				Status:      StatusWarn,
				Expected:    "separate partition",
				Actual:      "part of root filesystem",
				Category:    "Filesystem Matrix",
			}
			results.AddFinding(finding)
		}
	}
}

// analyzePartitionLayout analyzes overall partition security layout
func (mc *MatrixChecker) analyzePartitionLayout(results *Results) {
	mounts, err := mc.getMatrixMountInfo()
	if err != nil {
		return
	}

	// Count and analyze partition types
	partitionTypes := make(map[string]int)
	encryptedCount := 0
	totalCount := len(mounts)

	for _, mount := range mounts {
		partitionTypes[mount.FSType]++

		// Check for encrypted partitions (basic detection)
		if strings.Contains(mount.Device, "crypt") ||
			strings.Contains(mount.Device, "luks") ||
			mount.FSType == "crypto_LUKS" {
			encryptedCount++
		}
	}

	// Analyze partition diversity
	finding := &Finding{
		ID:          "MATRIX_PARTITION_LAYOUT",
		Title:       fmt.Sprintf("Filesystem Matrix layout [%d partitions, %d encrypted]", totalCount, encryptedCount),
		Description: "Overall filesystem security layout analysis",
		Severity:    SeverityInfo,
		Status:      StatusInfo,
		Expected:    "secure partition layout",
		Actual: fmt.Sprintf("%d total, %d encrypted (%.1f%%)", totalCount, encryptedCount,
			float64(encryptedCount)/float64(totalCount)*100),
		Category: "Filesystem Matrix",
	}
	results.AddFinding(finding)

	// Check for encryption usage
	if encryptedCount == 0 {
		finding := &Finding{
			ID:          "MATRIX_NO_ENCRYPTION",
			Title:       "No encrypted filesystems detected [HIGH_RISK]",
			Description: "No encrypted partitions found - data at risk if system compromised",
			Severity:    SeverityHigh,
			Status:      StatusFail,
			Expected:    "encrypted sensitive partitions",
			Actual:      "no encryption detected",
			Category:    "Filesystem Matrix",
			Exploitable: true,
		}
		results.AddFinding(finding)
	}
}

// performAdvancedMatrixAnalysis conducts deep filesystem analysis
func (mc *MatrixChecker) performAdvancedMatrixAnalysis(results *Results) {
	mc.logger.Debug("Performing advanced filesystem matrix analysis...")

	// Analyze inode limits and usage
	mc.analyzeInodeLimits(results)

	// Check for filesystem anomalies
	mc.detectFilesystemAnomalies(results)

	// Scan for alternate data streams (if supported)
	mc.scanAlternateDataStreams(results)

	// Check filesystem journal security
	mc.analyzeJournalSecurity(results)
}

// scanHiddenFilesystems looks for hidden or suspicious filesystems
func (mc *MatrixChecker) scanHiddenFilesystems(results *Results) {
	// Check for loop devices and hidden mounts
	loopDevices, err := utils.ExecuteCommand("losetup", "-a")
	if err == nil && strings.TrimSpace(loopDevices) != "" {
		lines := strings.Split(loopDevices, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				finding := &Finding{
					ID:          fmt.Sprintf("MATRIX_HIDDEN_LOOP_%x", sha256.Sum256([]byte(line))),
					Title:       "Hidden loop device detected",
					Description: "Loop device mounted - potential hidden filesystem or rootkit",
					Severity:    SeverityMedium,
					Status:      StatusWarn,
					Expected:    "no suspicious loop devices",
					Actual:      line,
					Category:    "Filesystem Matrix",
					Exploitable: true,
				}
				results.AddFinding(finding)
			}
		}
	}

	// Check for bind mounts (can hide files)
	mc.detectBindMounts(results)

	// Look for unusual filesystem types in /proc/filesystems
	mc.scanUnusualFilesystems(results)
}

// detectBindMounts checks for potentially suspicious bind mounts
func (mc *MatrixChecker) detectBindMounts(results *Results) {
	mounts, err := mc.getMatrixMountInfo()
	if err != nil {
		return
	}

	bindMounts := 0
	for _, mount := range mounts {
		if mc.hasMountOption(mount.Options, "bind") {
			bindMounts++

			// Check if bind mount might be hiding something
			suspicious := false
			suspiciousPaths := []string{"/etc", "/root", "/home", "/var/log"}

			for _, suspPath := range suspiciousPaths {
				if strings.HasPrefix(mount.MountPoint, suspPath) {
					suspicious = true
					break
				}
			}

			if suspicious {
				finding := &Finding{
					ID:          fmt.Sprintf("MATRIX_SUSPICIOUS_BIND_%x", sha256.Sum256([]byte(mount.MountPoint))),
					Title:       fmt.Sprintf("Suspicious bind mount: %s", mount.MountPoint),
					Description: "Bind mount on sensitive directory - potential file hiding",
					Severity:    SeverityMedium,
					Status:      StatusWarn,
					Expected:    "no suspicious bind mounts",
					Actual:      fmt.Sprintf("%s -> %s", mount.Device, mount.MountPoint),
					Category:    "Filesystem Matrix",
					Exploitable: true,
				}
				results.AddFinding(finding)
			}
		}
	}

	if bindMounts > 0 {
		finding := &Finding{
			ID:          "MATRIX_BIND_MOUNTS_COUNT",
			Title:       fmt.Sprintf("Bind mounts detected: %d", bindMounts),
			Description: "Number of bind mounts in filesystem matrix",
			Severity:    SeverityInfo,
			Status:      StatusInfo,
			Expected:    "minimal bind mounts",
			Actual:      fmt.Sprintf("%d bind mounts", bindMounts),
			Category:    "Filesystem Matrix",
		}
		results.AddFinding(finding)
	}
}

// Helper functions for filesystem analysis

func (mc *MatrixChecker) isFilesystemLoaded(fsType string) bool {
	// Check /proc/modules
	if modules, err := utils.ReadLines("/proc/modules"); err == nil {
		for _, module := range modules {
			if strings.HasPrefix(module, fsType+" ") {
				return true
			}
		}
	}

	// Check /proc/filesystems
	if filesystems, err := utils.ReadLines("/proc/filesystems"); err == nil {
		for _, fs := range filesystems {
			if strings.Contains(fs, fsType) {
				return true
			}
		}
	}

	return false
}

func (mc *MatrixChecker) isFilesystemAvailable(fsType string) bool {
	// Check if filesystem module exists
	modulePaths := []string{
		"/lib/modules/" + mc.getKernelVersion() + "/kernel/fs/" + fsType,
		"/lib/modules/" + mc.getKernelVersion() + "/kernel/fs/" + fsType + "/" + fsType + ".ko",
	}

	for _, path := range modulePaths {
		if utils.FileExists(path) {
			return true
		}
	}

	return false
}

func (mc *MatrixChecker) getMatrixMountInfo() ([]MatrixMountInfo, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var mounts []MatrixMountInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			mounts = append(mounts, MatrixMountInfo{
				Device:     fields[0],
				MountPoint: fields[1],
				FSType:     fields[2],
				Options:    strings.Split(fields[3], ","),
			})
		}
	}

	return mounts, scanner.Err()
}

func (mc *MatrixChecker) hasMountOption(options []string, target string) bool {
	for _, opt := range options {
		if opt == target {
			return true
		}
	}
	return false
}

func (mc *MatrixChecker) getKernelVersion() string {
	if output, err := utils.ExecuteCommand("uname", "-r"); err == nil {
		return strings.TrimSpace(output)
	}
	return "unknown"
}

// Additional analysis functions (placeholder implementations)

func (mc *MatrixChecker) analyzeInodeLimits(results *Results) {
	// Analyze inode usage across filesystems
	finding := &Finding{
		ID:          "MATRIX_INODE_ANALYSIS",
		Title:       "Filesystem inode analysis",
		Description: "Inode usage and limits across filesystem matrix",
		Severity:    SeverityInfo,
		Status:      StatusInfo,
		Expected:    "adequate inode availability",
		Actual:      "requires detailed analysis",
		Category:    "Filesystem Matrix",
	}
	results.AddFinding(finding)
}

func (mc *MatrixChecker) detectFilesystemAnomalies(results *Results) {
	// Look for filesystem inconsistencies and anomalies
	finding := &Finding{
		ID:          "MATRIX_ANOMALY_SCAN",
		Title:       "Filesystem anomaly detection",
		Description: "Scan for filesystem inconsistencies and anomalies",
		Severity:    SeverityInfo,
		Status:      StatusInfo,
		Expected:    "no anomalies detected",
		Actual:      "requires forensic analysis",
		Category:    "Filesystem Matrix",
	}
	results.AddFinding(finding)
}

func (mc *MatrixChecker) scanAlternateDataStreams(results *Results) {
	// Check for NTFS alternate data streams if NTFS is mounted
	// This is mainly relevant for forensic analysis
}

func (mc *MatrixChecker) analyzeJournalSecurity(results *Results) {
	// Analyze filesystem journal security settings
}

func (mc *MatrixChecker) analyzeFilesystemLimits(results *Results) {
	// Check filesystem quotas and user limits
}

func (mc *MatrixChecker) scanUnusualFilesystems(results *Results) {
	// Scan for unusual or potentially malicious filesystem types
}

// Remediation functions

func (mc *MatrixChecker) getFilesystemRemediation(fsType string) string {
	return fmt.Sprintf(`◢◤ FILESYSTEM MATRIX REMEDIATION:
┌─ Blacklist module: echo 'blacklist %s' >> /etc/modprobe.d/blacklist.conf
├─ Remove module: rmmod %s (if loaded)
├─ Rebuild initrd: update-initramfs -u
└─ Verify: lsmod | grep %s`, fsType, fsType, fsType)
}

func (mc *MatrixChecker) getMountRemediation(mountPoint, option string) string {
	return fmt.Sprintf(`◢◤ MOUNT SECURITY REMEDIATION:
┌─ Edit fstab: sudo nano /etc/fstab
├─ Add option: %s to %s mount line
├─ Example: UUID=xxx %s ext4 defaults,%s 0 2
├─ Test mount: sudo mount -o remount %s
└─ Verify: mount | grep %s`, option, mountPoint, mountPoint, option, mountPoint, mountPoint)
}
