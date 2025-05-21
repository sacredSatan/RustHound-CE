package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// ResourceMonitor holds configuration for resource monitoring
type ResourceMonitor struct {
	MinDiskSpaceMB   uint64
	MaxMemoryUsageMB uint64
	CheckIntervalSec int
	OutputDir        string
	Process          *os.Process
	StopMonitoring   chan bool
	Debug            bool
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(minDiskSpaceMB, maxMemoryUsageMB uint64, checkIntervalSec int, outputDir string, process *os.Process, debug bool) *ResourceMonitor {
	return &ResourceMonitor{
		MinDiskSpaceMB:   minDiskSpaceMB,
		MaxMemoryUsageMB: maxMemoryUsageMB,
		CheckIntervalSec: checkIntervalSec,
		OutputDir:        outputDir,
		Process:          process,
		StopMonitoring:   make(chan bool),
		Debug:            debug,
	}
}

// logDebug prints a debug message only if debug mode is enabled
func (r *ResourceMonitor) logDebug(format string, args ...interface{}) {
	if r.Debug {
		fmt.Fprintf(os.Stderr, "DEBUG: "+format+"\n", args...)
	}
}

// terminateProcess attempts to kill the monitored process and exits the program
func (r *ResourceMonitor) terminateProcess(reason string) {
	fmt.Fprintf(os.Stderr, "Critical: %s. Terminating process.\n", reason)
	r.logDebug("Attempting to kill process with PID: %d", r.Process.Pid)

	err := r.Process.Kill()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to kill process: %v\n", err)
	} else {
		r.logDebug("Process.Kill() returned without error")

		// Double check if process is still running after kill
		time.Sleep(500 * time.Millisecond)
		stillAlive := false

		// Try more forceful termination using syscall
		r.logDebug("Attempting to verify if process is dead")

		// First check using os.FindProcess - this doesn't actually check if the process exists on Linux
		// but we'll use it anyway and then check with a signal
		proc, err := os.FindProcess(r.Process.Pid)
		if err != nil {
			r.logDebug("FindProcess error: %v - process may be gone", err)
		} else {
			// On Linux, FindProcess almost always succeeds, so test with Signal(0)
			err = proc.Signal(syscall.Signal(0))
			if err != nil {
				r.logDebug("Process appears to be gone (Signal(0) error: %v)", err)
			} else {
				r.logDebug("Process still exists after Kill(), attempting SIGKILL directly")
				stillAlive = true

				// Try a direct syscall for SIGKILL
				err = syscall.Kill(r.Process.Pid, syscall.SIGKILL)
				if err != nil {
					fmt.Fprintf(os.Stderr, "ERROR: Failed to send SIGKILL: %v\n", err)
				} else {
					r.logDebug("SIGKILL sent successfully")

					// Final verification
					time.Sleep(500 * time.Millisecond)
					err = syscall.Kill(r.Process.Pid, syscall.Signal(0))
					if err != nil {
						r.logDebug("Process appears to be gone after SIGKILL")
					} else {
						fmt.Fprintf(os.Stderr, "WARNING: Process still exists even after SIGKILL! PID: %d\n", r.Process.Pid)
					}
				}
			}
		}

		// Check if there are child processes with the same name
		if stillAlive {
			r.logDebug("Checking for child processes")
			listProcessTree(r.Process.Pid, r.Debug)
		}
	}

	fmt.Fprintf(os.Stderr, "INFO: Exiting wrapper after terminating process\n")
	os.Exit(1)
}

// StartMonitoring begins monitoring system resources
func (r *ResourceMonitor) StartMonitoring() {
	go func() {
		ticker := time.NewTicker(time.Duration(r.CheckIntervalSec) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Check available disk space
				diskSpaceMB, err := getAvailableDiskSpaceMB(r.OutputDir)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to check disk space: %v\n", err)
				} else if diskSpaceMB < r.MinDiskSpaceMB {
					reason := fmt.Sprintf("Available disk space (%d MB) is below minimum threshold (%d MB)",
						diskSpaceMB, r.MinDiskSpaceMB)
					r.terminateProcess(reason)
				}

				// Check memory usage
				memUsageMB, err := getProcessMemoryUsageMB(r.Process.Pid, r.Debug)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to check memory usage: %v\n", err)
				} else if memUsageMB > r.MaxMemoryUsageMB {
					reason := fmt.Sprintf("Process memory usage (%d MB) exceeds maximum threshold (%d MB)",
						memUsageMB, r.MaxMemoryUsageMB)
					r.terminateProcess(reason)
				}

				// Only log resource check if debug is enabled
				if r.Debug {
					fmt.Printf("Resource check: Disk space: %d MB available, Memory usage: %d MB\n", diskSpaceMB, memUsageMB)
				}

			case <-r.StopMonitoring:
				return
			}
		}
	}()
}

// StopMonitoring stops the resource monitoring
func (r *ResourceMonitor) Stop() {
	r.StopMonitoring <- true
}
