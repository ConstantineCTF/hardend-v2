package checks

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/ConstantineCTF/hardend/pkg/utils" // Ensure this import path is correct
)

// FilesystemChecker handles filesystem security analysis
type FilesystemChecker struct {
	logger   *utils.Logger // Corrected: Use Logger
	stealth  bool
	advanced bool // Flag to potentially show more details or INFO checks
}

// NewFilesystemChecker creates a new filesystem analyzer
func NewFilesystemChecker(verbose, stealth, advanced bool) *FilesystemChecker {
	return &FilesystemChecker{
		logger:   utils.NewLogger(verbose, stealth), // Corrected: Use NewLogger
		stealth:  stealth,
		advanced: advanced,
	}
}

// MountInfo represents mount point information
type MountInfo struct {
	Device     string
	MountPoint string
	FSType     string
	Options    []string
}

// RunChecks performs comprehensive filesystem security analysis
func (mc *FilesystemChecker) RunChecks(results *Results) error {
	mc.logger.Info("Initiating filesystem scan...")

	mc.scanDangerousFilesystemModules(results)
	mc.analyzeMountSecurity(results)
	mc.analyzePartitionLayout(results) // Basic check for separate partitions/encryption

	mc.logger.Info("Filesystem scan complete.")
	return nil
}

// scanDangerousFilesystemModules checks for loaded or available dangerous filesystem kernel modules
func (mc *FilesystemChecker) scanDangerousFilesystemModules(results *Results) {
	// TODO: Load this list from config.yaml
	dangerousFS := map[string]string{
		"cramfs":   "Legacy compressed ROM filesystem - rarely needed.",
		"freevxfs": "Veritas filesystem - legacy, proprietary.",
		"jffs2":    "Journaling Flash filesystem - typically for embedded devices.",
		"hfs":      "Legacy Apple HFS - should not be needed on Linux servers.",
		"hfsplus":  "Apple HFS+ - should not be needed on Linux servers.",
		"udf":      "Universal Disk Format - typically for optical media, potential vulnerabilities.",
		"squashfs": "Read-only compressed filesystem. Loading it isn't inherently bad, but check usage.", // Lower severity
	}

	for fsType, desc := range dangerousFS {
		mc.logger.Debug("Checking filesystem module: %s", fsType)
		loaded := mc.isFilesystemModuleLoaded(fsType)
		// Check availability only if not loaded? Or always? Let's check always for info.
		available := mc.isFilesystemModuleAvailable(fsType)

		status := StatusPass
		severity := SeverityLow // Default low for availability
		exploitable := false
		actual := "Module not loaded and not found."

		if loaded {
			status = StatusFail
			severity = SeverityHigh // Loading these is generally bad practice on servers
			if fsType == "squashfs" {
				severity = SeverityLow
			} // squashfs is common, make it low impact if loaded
			exploitable = true // Could potentially be exploited if loaded unnecessarily
			actual = "Module is loaded."
		} else if available {
			status = StatusInfo // Changed Warn to Info for availability
			actual = "Module is available but not loaded."
			// Don't add finding for 'available' unless in advanced mode
			if !mc.advanced {
				continue
			}
		} else {
			// Not loaded, not available - perfect. Don't add finding unless advanced.
			if !mc.advanced {
				continue
			}
		}

		finding := &Finding{
			ID:          fmt.Sprintf("FS_MODULE_%s", strings.ToUpper(fsType)),
			Title:       fmt.Sprintf("Filesystem module '%s' status", fsType),
			Description: desc,
			Severity:    severity,
			Status:      status,
			Expected:    "Module should ideally be disabled or uninstalled.",
			Actual:      actual,
			Remediation: mc.getFilesystemRemediation(fsType),
			Category:    "Filesystem Modules", // More specific category
			Exploitable: exploitable,
		}
		results.AddFinding(finding)

	}
}

// analyzeMountSecurity checks mount options and separate partitions
func (mc *FilesystemChecker) analyzeMountSecurity(results *Results) {
	mounts, err := mc.getMountInfo()
	if err != nil {
		mc.logger.Error("Failed to read mount info: %v", err)
		// Add a finding indicating failure to read mounts
		finding := &Finding{
			ID:          "FS_READ_MOUNTS_ERROR",
			Title:       "Failed to read system mount points",
			Description: fmt.Sprintf("Error reading /proc/mounts: %v", err),
			Severity:    SeverityMedium,
			Status:      StatusSkip,
			Category:    "Filesystem",
		}
		results.AddFinding(finding)
		return
	}

	// TODO: Load criticalMounts rules from config.yaml
	criticalMounts := map[string][]string{
		"/tmp":     {"nosuid", "noexec", "nodev"},
		"/var/tmp": {"nosuid", "noexec", "nodev"},
		"/dev/shm": {"nosuid", "noexec", "nodev"},
		"/home":    {"nodev"}, // CIS recommends nodev for /home. nosuid is also good practice.
		// Add others as needed based on CIS/STIG, e.g., /var, /var/log, /var/log/audit
		// "/var":     {"nosuid"}, // Example
		// "/boot":    {"nosuid", "nodev", "noexec"}, // If /boot is separate
	}

	mountMap := make(map[string]MountInfo)
	for _, mount := range mounts {
		mountMap[mount.MountPoint] = mount
	}

	// Check if critical paths are on separate partitions
	for mountPoint := range criticalMounts {
		if _, exists := mountMap[mountPoint]; !exists {
			finding := &Finding{
				ID:          fmt.Sprintf("FS_PARTITION_%s", strings.ToUpper(strings.ReplaceAll(mountPoint, "/", "_"))),
				Title:       fmt.Sprintf("'%s' is not on a separate partition", mountPoint),
				Description: fmt.Sprintf("Placing %s on a separate partition helps contain issues like disk space exhaustion and allows specific mount options.", mountPoint),
				Severity:    SeverityMedium, // Often Medium, depends on the path
				Status:      StatusWarn,     // Warning, not a direct failure
				Expected:    "Separate filesystem partition",
				Actual:      "Part of another filesystem (likely root)",
				Category:    "Filesystem Partitions", // Specific category
				Remediation: fmt.Sprintf("Consider repartitioning the system to place %s on its own dedicated filesystem.", mountPoint),
			}
			results.AddFinding(finding)
		}
	}

	// Check mount options for existing partitions
	for _, mount := range mounts {
		requiredOpts, isCritical := criticalMounts[mount.MountPoint]
		if !isCritical {
			continue // Only check options for the paths defined in criticalMounts
		}

		mc.logger.Debug("Checking options for mount point: %s", mount.MountPoint)
		currentOptsStr := strings.Join(mount.Options, ",")

		for _, requiredOpt := range requiredOpts {
			if !mc.hasMountOption(mount.Options, requiredOpt) {
				status := StatusFail
				severity := SeverityMedium
				exploitable := true // Missing security options often aid exploitation

				// Elevate severity for critical options like noexec/nosuid on /tmp etc.
				if (mount.MountPoint == "/tmp" || mount.MountPoint == "/var/tmp" || mount.MountPoint == "/dev/shm") &&
					(requiredOpt == "noexec" || requiredOpt == "nosuid") {
					severity = SeverityHigh
				}
				if mount.MountPoint == "/home" && requiredOpt == "nosuid" { // If checking nosuid on /home
					severity = SeverityMedium
				}

				finding := &Finding{
					ID: fmt.Sprintf("FS_MOUNT_%s_%s",
						strings.ToUpper(strings.ReplaceAll(mount.MountPoint, "/", "_")),
						strings.ToUpper(requiredOpt)),
					Title:       fmt.Sprintf("Mount '%s' missing option '%s'", mount.MountPoint, requiredOpt),
					Description: fmt.Sprintf("The '%s' filesystem mount is missing the recommended '%s' security option.", mount.MountPoint, requiredOpt),
					Severity:    severity,
					Status:      status,
					Expected:    fmt.Sprintf("'%s' option present", requiredOpt),
					Actual:      currentOptsStr,
					Remediation: mc.getMountRemediation(mount.MountPoint, requiredOpt),
					Category:    "Filesystem Mount Options", // Specific category
					Exploitable: exploitable,
				}
				results.AddFinding(finding)
			}
		}
	}
}

// analyzePartitionLayout provides a basic check for encryption (LUKS)
func (mc *FilesystemChecker) analyzePartitionLayout(results *Results) {
	mounts, err := mc.getMountInfo()
	if err != nil {
		// Error already logged by analyzeMountSecurity if it was called first
		return
	}

	encryptedCount := 0
	hasRootFS := false
	isRootEncrypted := false

	for _, mount := range mounts {
		isEncrypted := strings.Contains(mount.Device, "/dev/mapper/crypt") || // Common pattern
			strings.Contains(mount.Device, "/dev/mapper/luks") ||
			mount.FSType == "crypto_LUKS" ||
			strings.HasPrefix(mount.Device, "/dev/dm-") // Sometimes used

		if isEncrypted {
			encryptedCount++
		}

		if mount.MountPoint == "/" {
			hasRootFS = true
			isRootEncrypted = isEncrypted
		}
	}

	// Report overall encryption status
	actualEncryption := fmt.Sprintf("%d encrypted partitions detected.", encryptedCount)
	severity := SeverityInfo
	status := StatusInfo
	if encryptedCount == 0 {
		severity = SeverityHigh
		status = StatusWarn // Warning as it's a configuration choice, but risky
		actualEncryption = "No filesystem encryption (e.g., LUKS) detected."
	}

	findingEncryption := &Finding{
		ID:          "FS_ENCRYPTION_STATUS",
		Title:       "Filesystem Encryption Check",
		Description: "Checks for the presence of encrypted partitions (e.g., LUKS). Encrypting sensitive data at rest is crucial.",
		Severity:    severity,
		Status:      status,
		Expected:    "Root filesystem and/or partitions with sensitive data should be encrypted.",
		Actual:      actualEncryption,
		Category:    "Filesystem Partitions",
		Remediation: "Consider using LUKS (Linux Unified Key Setup) to encrypt filesystems during OS installation or by migrating data.",
		Exploitable: encryptedCount == 0, // Data physically exploitable
	}
	results.AddFinding(findingEncryption)

	// Specifically check if root filesystem is encrypted (often a key requirement)
	if hasRootFS {
		statusRoot := StatusInfo
		severityRoot := SeverityInfo
		if !isRootEncrypted {
			statusRoot = StatusWarn
			severityRoot = SeverityHigh
		}
		findingRootEnc := &Finding{
			ID:          "FS_ROOT_ENCRYPTION",
			Title:       "Root Filesystem Encryption Status",
			Description: "Checks if the root filesystem ('/') appears to be encrypted.",
			Severity:    severityRoot,
			Status:      statusRoot,
			Expected:    "Root filesystem encrypted (recommended).",
			Actual:      fmt.Sprintf("Root filesystem encrypted: %t", isRootEncrypted),
			Category:    "Filesystem Partitions",
			Remediation: "Encrypting the root filesystem is best done during OS installation.",
			Exploitable: !isRootEncrypted,
		}
		// Add this finding only if root wasn't encrypted or in advanced mode
		if !isRootEncrypted || mc.advanced {
			results.AddFinding(findingRootEnc)
		}
	}
}

// --- Helper Functions ---

// isFilesystemModuleLoaded checks /proc/modules and /proc/filesystems
func (mc *FilesystemChecker) isFilesystemModuleLoaded(fsType string) bool {
	// Check loaded modules
	modulesContent, err := os.ReadFile("/proc/modules")
	if err == nil {
		if strings.Contains(string(modulesContent), fsType+" ") {
			return true
		}
	} else {
		mc.logger.Debug("Could not read /proc/modules: %v", err)
	}

	// Check built-in filesystems (or currently used)
	filesystemsContent, err := os.ReadFile("/proc/filesystems")
	if err == nil {
		lines := strings.Split(string(filesystemsContent), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			// Check second column which usually contains the fs type name
			if len(parts) > 0 {
				// Handle 'nodev' prefix if present
				fsName := parts[0]
				if fsName == "nodev" && len(parts) > 1 {
					fsName = parts[1]
				}
				if fsName == fsType {
					return true // Filesystem type is known/supported by the kernel
				}
			}
		}
	} else {
		mc.logger.Debug("Could not read /proc/filesystems: %v", err)
	}

	return false
}

// isFilesystemModuleAvailable checks if the kernel module file exists
func (mc *FilesystemChecker) isFilesystemModuleAvailable(fsType string) bool {
	kernelVersion := utils.GetKernelVersion()
	if kernelVersion == "unknown" {
		return false // Cannot determine path without kernel version
	}
	// Standard path pattern for kernel modules
	moduleDir := fmt.Sprintf("/lib/modules/%s/kernel/fs/%s/", kernelVersion, fsType)
	moduleFile := fmt.Sprintf("%s%s.ko", moduleDir, fsType) // Assumes module name matches fsType

	// Check if either the directory or the .ko file exists
	if _, err := os.Stat(moduleDir); err == nil {
		// Check for the specific .ko file as well, directory might exist but be empty
		if _, err := os.Stat(moduleFile); err == nil {
			return true
		}
	}
	// Fallback check in general fs dir
	moduleFileAlt := fmt.Sprintf("/lib/modules/%s/kernel/fs/%s.ko", kernelVersion, fsType)
	if _, err := os.Stat(moduleFileAlt); err == nil {
		return true
	}

	return false
}

// getMountInfo parses /proc/mounts to get current mount points
func (mc *FilesystemChecker) getMountInfo() ([]MountInfo, error) {
	// Using /proc/mounts provides the most current view of mounts
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("could not open /proc/mounts: %w", err)
	}
	defer file.Close()

	var mounts []MountInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// Expected format: device mount_point fs_type options dump pass
		if len(fields) >= 4 {
			mounts = append(mounts, MountInfo{
				Device:     fields[0],
				MountPoint: fields[1],
				FSType:     fields[2],
				Options:    strings.Split(fields[3], ","), // Options are comma-separated
			})
		} else {
			mc.logger.Debug("Skipping malformed line in /proc/mounts: %s", line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /proc/mounts: %w", err)
	}

	return mounts, nil
}

// hasMountOption checks if a specific option exists in the list of mount options
func (mc *FilesystemChecker) hasMountOption(options []string, target string) bool {
	for _, opt := range options {
		if opt == target {
			return true
		}
	}
	return false
}

// --- Remediation Functions ---

// getFilesystemRemediation provides instructions to disable a filesystem module
func (mc *FilesystemChecker) getFilesystemRemediation(fsType string) string {
	// Provide instructions for both blacklisting and potentially uninstalling kernel modules
	return fmt.Sprintf(
		"To prevent loading: Add 'install %s /bin/true' to a file in '/etc/modprobe.d/'.\nOptionally, blacklist: 'echo \"blacklist %s\" >> /etc/modprobe.d/blacklist-%s.conf'.\nRebuild initramfs ('sudo update-initramfs -u' on Debian/Ubuntu, 'sudo dracut -f' on RHEL/Fedora) and reboot.",
		fsType, fsType, fsType)
}

// getMountRemediation provides instructions to add a mount option via fstab
func (mc *FilesystemChecker) getMountRemediation(mountPoint, option string) string {
	// Recommend editing fstab for persistence
	return fmt.Sprintf(
		"To fix permanently: Edit '/etc/fstab' and add the '%s' option to the options field for the '%s' mount point.\nExample: 'UUID=... %s ext4 defaults,errors=remount-ro,%s 0 2'.\nThen run 'sudo mount -o remount %s' to apply temporarily or reboot.",
		option, mountPoint, mountPoint, option, mountPoint)
}
