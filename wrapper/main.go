package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	// Find the index of "--" if present
	delimiterIndex := -1
	for i, arg := range os.Args {
		if arg == "--" {
			delimiterIndex = i
			break
		}
	}

	// Setup a custom FlagSet for our wrapper flags
	wrapperFlags := flag.NewFlagSet("wrapper", flag.ExitOnError)
	wrapperFlags.Usage = func() {
		fmt.Println("RustHound-CE Wrapper - A resource monitoring wrapper for RustHound-CE")
		fmt.Println("")
		fmt.Println("Usage:")
		fmt.Println("  rusthound-wrapper [wrapper options] [-- rusthound-ce options]")
		fmt.Println("")
		fmt.Println("Wrapper Options:")
		wrapperFlags.PrintDefaults()
		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("  rusthound-wrapper --min-disk 1000 --max-memory 4096 -- -u username -p password -d domain.com")
		fmt.Println("  rusthound-wrapper -- -o /custom/output/dir -u user@domain.com -p password")
	}

	// Define flags for resource monitoring
	minDiskSpace := wrapperFlags.Uint64("min-disk", 500, "Minimum disk space in MB before terminating")
	maxMemory := wrapperFlags.Uint64("max-memory", 2048, "Maximum memory usage in MB before terminating")
	checkInterval := wrapperFlags.Int("check-interval", 1, "Resource check interval in seconds")
	monitoringEnabled := wrapperFlags.Bool("monitor", true, "Enable resource monitoring")
	skipPrerequisites := wrapperFlags.Bool("skip-checks", false, "Skip prerequisite checks")
	debugMode := wrapperFlags.Bool("debug", false, "Enable debug logging")

	// Process arguments
	var argsToPass []string
	if delimiterIndex == -1 {
		// No delimiter, try to parse all arguments as wrapper flags
		// Any unknown flags will fail
		if err := wrapperFlags.Parse(os.Args[1:]); err != nil {
			// If parsing fails, assume all args are for RustHound-CE
			argsToPass = os.Args[1:]
		} else {
			// Successfully parsed all flags
			// Everything after the parsed flags should go to RustHound-CE
			argsToPass = wrapperFlags.Args()
		}
	} else {
		// Delimiter found, parse only the wrapper flags before the delimiter
		if delimiterIndex > 1 {
			if err := wrapperFlags.Parse(os.Args[1:delimiterIndex]); err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing wrapper flags: %v\n", err)
				wrapperFlags.Usage()
				os.Exit(1)
			}
		}
		// Everything after the delimiter goes to RustHound-CE
		if delimiterIndex < len(os.Args)-1 {
			argsToPass = os.Args[delimiterIndex+1:]
		}
	}

	// Default output directory where RustHound-CE stores its files
	outputDir := "./output"

	// Check for output directory in rusthound args
	for i := 0; i < len(argsToPass)-1; i++ {
		if argsToPass[i] == "-o" || argsToPass[i] == "--outdir" {
			outputDir = argsToPass[i+1]
			break
		}
	}

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Run prerequisite checks if not skipped
	if !*skipPrerequisites {
		checksPassed := runPrerequisiteChecks(argsToPass, outputDir, *minDiskSpace, *maxMemory)
		if !checksPassed {
			fmt.Fprintf(os.Stderr, "\nOne or more prerequisite checks failed. Fix the issues or use --skip-checks to bypass.\n")
			os.Exit(1)
		}
	}

	// Prepare the command to run RustHound-CE with all provided arguments
	cmd := exec.Command("/app/rusthound-ce")

	// Pass the filtered arguments to RustHound-CE
	if len(argsToPass) > 0 {
		cmd.Args = append(cmd.Args, argsToPass...)
	}

	// Set up the command to use the same standard input, output, and error as this program
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Execute RustHound-CE in the background so we can monitor it
	fmt.Println("\nExecuting RustHound-CE with arguments:", strings.Join(argsToPass, " "))

	// Resource monitoring information
	if *monitoringEnabled {
		fmt.Printf("Resource monitoring enabled:\n")
		fmt.Printf("- Minimum disk space: %d MB\n", *minDiskSpace)
		fmt.Printf("- Maximum memory usage: %d MB\n", *maxMemory)
		fmt.Printf("- Check interval: %d seconds\n", *checkInterval)
	}

	// Start the process
	err := cmd.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting RustHound-CE: %v\n", err)
		os.Exit(1)
	}

	// Get the process ID for monitoring
	pid := cmd.Process.Pid
	fmt.Printf("RustHound-CE started with PID: %d\n", pid)
	fmt.Fprintf(os.Stderr, "DEBUG: Process details - PID: %d, Process: %+v\n", pid, cmd.Process)

	// Set up resource monitoring if enabled
	var monitor *ResourceMonitor
	if *monitoringEnabled {
		monitor = NewResourceMonitor(*minDiskSpace, *maxMemory, *checkInterval, outputDir, cmd.Process, *debugMode)
		monitor.StartMonitoring()
	}

	// Wait for the command to complete
	fmt.Fprintf(os.Stderr, "DEBUG: Waiting for process to complete...\n")
	err = cmd.Wait()
	fmt.Fprintf(os.Stderr, "DEBUG: Process Wait() completed with error: %v\n", err)

	// Stop monitoring
	if *monitoringEnabled && monitor != nil {
		fmt.Fprintf(os.Stderr, "DEBUG: Stopping resource monitor\n")
		monitor.Stop()
	}

	// Check if process was terminated due to resource constraints
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			fmt.Fprintf(os.Stderr, "RustHound-CE exited with an error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Error executing RustHound-CE: %v\n", err)
			// If the error contains "killed" it was likely terminated by our monitor
			if strings.Contains(err.Error(), "killed") {
				fmt.Fprintf(os.Stderr, "Process was terminated due to resource constraints, exiting wrapper\n")
				os.Exit(1)
			}
		}
	} else {
		fmt.Println("\nRustHound-CE completed successfully.")
	}

	// List all files generated by RustHound-CE
	fmt.Println("\nFiles generated by RustHound-CE:")

	fileCount := 0
	totalBytes := int64(0)

	err = filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			relPath, err := filepath.Rel(outputDir, path)
			if err != nil {
				relPath = path
			}
			fmt.Printf("- %s (%d bytes)\n", relPath, info.Size())
			fileCount++
			totalBytes += info.Size()
		}
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing files: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSummary: Generated %d files, total size %d bytes (%.2f MB)\n",
		fileCount, totalBytes, float64(totalBytes)/(1024*1024))
}
