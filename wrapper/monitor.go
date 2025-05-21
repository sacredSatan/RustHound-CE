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
}

// NewResourceMonitor creates a new resource monitor
func NewResourceMonitor(minDiskSpaceMB, maxMemoryUsageMB uint64, checkIntervalSec int, outputDir string, process *os.Process) *ResourceMonitor {
	return &ResourceMonitor{
		MinDiskSpaceMB:   minDiskSpaceMB,
		MaxMemoryUsageMB: maxMemoryUsageMB,
		CheckIntervalSec: checkIntervalSec,
		OutputDir:        outputDir,
		Process:          process,
		StopMonitoring:   make(chan bool),
	}
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
					fmt.Fprintf(os.Stderr, "Critical: Available disk space (%d MB) is below minimum threshold (%d MB). Terminating process.\n",
						diskSpaceMB, r.MinDiskSpaceMB)
					fmt.Fprintf(os.Stderr, "DEBUG: Attempting to kill process with PID: %d\n", r.Process.Pid)
					err := r.Process.Kill()
					if err != nil {
						fmt.Fprintf(os.Stderr, "ERROR: Failed to kill process: %v\n", err)
					} else {
						fmt.Fprintf(os.Stderr, "DEBUG: Process.Kill() returned without error\n")
					}
					return
				}

				// Check memory usage
				memUsageMB, err := getProcessMemoryUsageMB(r.Process.Pid)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Warning: Failed to check memory usage: %v\n", err)
				} else if memUsageMB > r.MaxMemoryUsageMB {
					fmt.Fprintf(os.Stderr, "Critical: Process memory usage (%d MB) exceeds maximum threshold (%d MB). Terminating process.\n",
						memUsageMB, r.MaxMemoryUsageMB)
					fmt.Fprintf(os.Stderr, "DEBUG: Attempting to kill process with PID: %d\n", r.Process.Pid)
					err := r.Process.Kill()
					if err != nil {
						fmt.Fprintf(os.Stderr, "ERROR: Failed to kill process: %v\n", err)
					} else {
						fmt.Fprintf(os.Stderr, "DEBUG: Process.Kill() returned without error\n")

						// Double check if process is still running after kill
						time.Sleep(500 * time.Millisecond)
						stillAlive := false

						// Try more forceful termination using syscall
						fmt.Fprintf(os.Stderr, "DEBUG: Attempting to verify if process is dead\n")

						// First check using os.FindProcess - this doesn't actually check if the process exists on Linux
						// but we'll use it anyway and then check with a signal
						proc, err := os.FindProcess(r.Process.Pid)
						if err != nil {
							fmt.Fprintf(os.Stderr, "DEBUG: FindProcess error: %v - process may be gone\n", err)
						} else {
							// On Linux, FindProcess almost always succeeds, so test with Signal(0)
							err = proc.Signal(syscall.Signal(0))
							if err != nil {
								fmt.Fprintf(os.Stderr, "DEBUG: Process appears to be gone (Signal(0) error: %v)\n", err)
							} else {
								fmt.Fprintf(os.Stderr, "DEBUG: Process still exists after Kill(), attempting SIGKILL directly\n")
								stillAlive = true

								// Try a direct syscall for SIGKILL
								err = syscall.Kill(r.Process.Pid, syscall.SIGKILL)
								if err != nil {
									fmt.Fprintf(os.Stderr, "ERROR: Failed to send SIGKILL: %v\n", err)
								} else {
									fmt.Fprintf(os.Stderr, "DEBUG: SIGKILL sent successfully\n")

									// Final verification
									time.Sleep(500 * time.Millisecond)
									err = syscall.Kill(r.Process.Pid, syscall.Signal(0))
									if err != nil {
										fmt.Fprintf(os.Stderr, "DEBUG: Process appears to be gone after SIGKILL\n")
									} else {
										fmt.Fprintf(os.Stderr, "WARNING: Process still exists even after SIGKILL! PID: %d\n", r.Process.Pid)
									}
								}
							}
						}

						// Check if there are child processes with the same name
						if stillAlive {
							fmt.Fprintf(os.Stderr, "DEBUG: Checking for child processes\n")
							listProcessTree(r.Process.Pid)
						}
					}

					// Force exit the entire program since we've terminated the child process
					fmt.Fprintf(os.Stderr, "INFO: Exiting wrapper after terminating process due to excessive memory usage\n")
					os.Exit(1)
				}

				fmt.Printf("Resource check: Disk space: %d MB available, Memory usage: %d MB\n", diskSpaceMB, memUsageMB)

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
