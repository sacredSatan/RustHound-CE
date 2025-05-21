package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// getAvailableDiskSpaceMB returns available disk space in MB
func getAvailableDiskSpaceMB(path string) (uint64, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	if err != nil {
		return 0, err
	}

	// Available blocks * block size
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	return availableBytes / (1024 * 1024), nil // Convert to MB
}

// getProcessMemoryUsageMB returns the memory usage of the process in MB
func getProcessMemoryUsageMB(pid int) (uint64, error) {
	// Linux-specific implementation using /proc filesystem
	procFile := fmt.Sprintf("/proc/%d/status", pid)
	fmt.Fprintf(os.Stderr, "DEBUG: Reading memory info from %s\n", procFile)

	data, err := os.ReadFile(procFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG: Error reading proc file: %v\n", err)
		return 0, err
	}

	// Parse the file to find memory usage (VmRSS)
	lines := strings.Split(string(data), "\n")
	fmt.Fprintf(os.Stderr, "DEBUG: Proc file contains %d lines\n", len(lines))

	for _, line := range lines {
		if strings.HasPrefix(line, "VmRSS:") {
			fmt.Fprintf(os.Stderr, "DEBUG: Found VmRSS line: %s\n", line)
			var memKB uint64
			_, err := fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "VmRSS:")), "%d kB", &memKB)
			if err != nil {
				fmt.Fprintf(os.Stderr, "DEBUG: Failed to parse memory usage: %v\n", err)
				return 0, fmt.Errorf("failed to parse memory usage: %v", err)
			}
			fmt.Fprintf(os.Stderr, "DEBUG: Calculated memory usage: %d KB (%d MB)\n", memKB, memKB/1024)
			return memKB / 1024, nil // Convert KB to MB
		}
	}

	fmt.Fprintf(os.Stderr, "DEBUG: Couldn't find VmRSS in proc file\n")
	return 0, fmt.Errorf("couldn't find memory usage information")
}

// getSystemMemoryInfoMB returns total and available memory in MB
func getSystemMemoryInfoMB() (uint64, uint64, error) {
	// Linux implementation using /proc/meminfo
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}

	lines := strings.Split(string(data), "\n")
	var totalKB, availableKB uint64

	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "MemTotal:")), "%d kB", &totalKB)
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "MemAvailable:")), "%d kB", &availableKB)
		}
	}

	return totalKB / 1024, availableKB / 1024, nil
}

// listProcessTree lists the process tree starting at the given PID
func listProcessTree(pid int) {
	fmt.Fprintf(os.Stderr, "DEBUG: Listing process tree for PID %d\n", pid)

	// Check if process exists
	_, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG: Process %d not found: %v\n", pid, err)
		return
	}

	// Run ps command to get child processes
	cmd := exec.Command("ps", "-eo", "pid,ppid,cmd")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG: Failed to run ps command: %v\n", err)
		return
	}

	lines := strings.Split(string(output), "\n")
	fmt.Fprintf(os.Stderr, "DEBUG: Found %d processes in system\n", len(lines)-1)

	// Print header
	fmt.Fprintf(os.Stderr, "DEBUG: Process tree:\n")
	fmt.Fprintf(os.Stderr, "DEBUG: PID     PPID    CMD\n")

	// First, print the main process
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			processPid := strings.TrimSpace(fields[0])
			if processPid == fmt.Sprintf("%d", pid) {
				fmt.Fprintf(os.Stderr, "DEBUG: %s\n", line)
				break
			}
		}
	}

	// Then find and print all child processes
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			processPpid := strings.TrimSpace(fields[1])
			if processPpid == fmt.Sprintf("%d", pid) {
				fmt.Fprintf(os.Stderr, "DEBUG: %s\n", line)
			}
		}
	}
}
