package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PrerequisiteCheck represents a check to be performed before running RustHound-CE
type PrerequisiteCheck struct {
	Name        string
	Description string
	Run         func() (bool, string)
	Fatal       bool // If true, failure of this check will prevent RustHound-CE from running
}

// checkLDAPConnectivity tests if we can reach the LDAP server
func checkLDAPConnectivity(ldapServer string, ldapPort int) (bool, string) {
	if ldapServer == "" {
		return true, "No LDAP server specified, skipping connectivity check"
	}

	address := fmt.Sprintf("%s:%d", ldapServer, ldapPort)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false, fmt.Sprintf("Cannot connect to LDAP server at %s: %v", address, err)
	}

	conn.Close()
	return true, fmt.Sprintf("Successfully connected to LDAP server at %s", address)
}

// checkDomainConnectivity tests if we can resolve and reach the domain
func checkDomainConnectivity(domain string) (bool, string) {
	if domain == "" {
		return true, "No domain specified, skipping connectivity check"
	}

	// Try to resolve the domain to IP addresses
	ips, err := net.LookupIP(domain)
	if err != nil {
		return false, fmt.Sprintf("Cannot resolve domain %s: %v", domain, err)
	}

	if len(ips) == 0 {
		return false, fmt.Sprintf("No IP addresses found for domain %s", domain)
	}

	// Try to connect to the domain controller on common ports
	dcPorts := []int{389, 636, 3268, 3269, 88}
	for _, ip := range ips {
		for _, port := range dcPorts {
			address := fmt.Sprintf("%s:%d", ip.String(), port)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err == nil {
				conn.Close()
				return true, fmt.Sprintf("Successfully connected to domain controller at %s", address)
			}
		}
	}

	// If we couldn't connect to any specific port, at least we could resolve the domain
	return true, fmt.Sprintf("Resolved domain %s to %v but couldn't connect to common DC ports", domain, ips)
}

// checkWritePermission tests if we can write to the output directory
func checkWritePermission(outputDir string) (bool, string) {
	testFile := filepath.Join(outputDir, ".write_test_"+fmt.Sprintf("%d", time.Now().UnixNano()))

	// Try to create a test file
	f, err := os.Create(testFile)
	if err != nil {
		return false, fmt.Sprintf("Cannot write to output directory %s: %v", outputDir, err)
	}

	// Write something to the file
	_, err = f.WriteString("Write test")
	f.Close()

	// Clean up
	os.Remove(testFile)

	if err != nil {
		return false, fmt.Sprintf("Cannot write to output directory %s: %v", outputDir, err)
	}

	return true, fmt.Sprintf("Successfully verified write permission to output directory %s", outputDir)
}

// checkDiskSpace tests if there's enough disk space
func checkDiskSpace(outputDir string, minDiskSpaceMB uint64) (bool, string) {
	availableMB, err := getAvailableDiskSpaceMB(outputDir)
	if err != nil {
		return false, fmt.Sprintf("Cannot check available disk space: %v", err)
	}

	if availableMB < minDiskSpaceMB {
		return false, fmt.Sprintf("Available disk space (%d MB) is below minimum threshold (%d MB)", availableMB, minDiskSpaceMB)
	}

	return true, fmt.Sprintf("Available disk space: %d MB (minimum required: %d MB)", availableMB, minDiskSpaceMB)
}

// checkAvailableMemory tests if there's enough available memory
func checkAvailableMemory(maxMemoryUsageMB uint64) (bool, string) {
	totalMB, availableMB, err := getSystemMemoryInfoMB()
	if err != nil {
		return false, fmt.Sprintf("Cannot check available memory: %v", err)
	}

	if availableMB < maxMemoryUsageMB {
		return false, fmt.Sprintf("Available memory (%d MB) is below the requested maximum memory usage (%d MB)", availableMB, maxMemoryUsageMB)
	}

	return true, fmt.Sprintf("Available memory: %d MB of %d MB total (maximum usage: %d MB)", availableMB, totalMB, maxMemoryUsageMB)
}

// runPrerequisiteChecks runs all prerequisite checks and returns true if all mandatory checks pass
func runPrerequisiteChecks(args []string, outputDir string, minDiskSpaceMB, maxMemoryUsageMB uint64) bool {
	logPrintln("\nRunning prerequisite checks...")

	// Define all checks to run
	checks := []PrerequisiteCheck{
		{
			Name:        "Disk Space",
			Description: "Check if there's enough disk space",
			Run:         func() (bool, string) { return checkDiskSpace(outputDir, minDiskSpaceMB) },
			Fatal:       true,
		},
		{
			Name:        "Available Memory",
			Description: "Check if there's enough available memory",
			Run:         func() (bool, string) { return checkAvailableMemory(maxMemoryUsageMB) },
			Fatal:       true,
		},
		{
			Name:        "Write Permission",
			Description: "Check if we can write to the output directory",
			Run:         func() (bool, string) { return checkWritePermission(outputDir) },
			Fatal:       true,
		},
	}

	// Run all checks
	allChecksPassed := true
	for _, check := range checks {
		logPrintf("- %s: ", check.Name)
		passed, message := check.Run()

		if passed {
			logPrintf("PASS - %s\n", message)
		} else {
			logPrintf("FAIL - %s\n", message)
			if check.Fatal {
				allChecksPassed = false
			}
		}
	}

	return allChecksPassed
}
