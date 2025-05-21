package main

import (
  "flag"
  "fmt"
  "os"
  "os/exec"
  "path/filepath"
  "strings"
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
        diskSpaceMB, err := r.getAvailableDiskSpaceMB()
        if err != nil {
          fmt.Fprintf(os.Stderr, "Warning: Failed to check disk space: %v\n", err)
        } else if diskSpaceMB < r.MinDiskSpaceMB {
          fmt.Fprintf(os.Stderr, "Critical: Available disk space (%d MB) is below minimum threshold (%d MB). Terminating process.\n",
            diskSpaceMB, r.MinDiskSpaceMB)
          r.Process.Kill()
          return
        }

        // Check memory usage
        memUsageMB, err := r.getProcessMemoryUsageMB()
        if err != nil {
          fmt.Fprintf(os.Stderr, "Warning: Failed to check memory usage: %v\n", err)
        } else if memUsageMB > r.MaxMemoryUsageMB {
          fmt.Fprintf(os.Stderr, "Critical: Process memory usage (%d MB) exceeds maximum threshold (%d MB). Terminating process.\n",
            memUsageMB, r.MaxMemoryUsageMB)
          r.Process.Kill()
          return
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

// getAvailableDiskSpaceMB returns available disk space in MB
func (r *ResourceMonitor) getAvailableDiskSpaceMB() (uint64, error) {
  var stat syscall.Statfs_t
  err := syscall.Statfs(r.OutputDir, &stat)
  if err != nil {
    return 0, err
  }

  // Available blocks * block size
  availableBytes := stat.Bavail * uint64(stat.Bsize)
  return availableBytes / (1024 * 1024), nil // Convert to MB
}

// getProcessMemoryUsageMB returns the memory usage of the process in MB
func (r *ResourceMonitor) getProcessMemoryUsageMB() (uint64, error) {
  // Read from /proc/{pid}/status to get memory usage
  // Note: This is Linux-specific, we'll need alternate implementations for other OSes
  procFile := fmt.Sprintf("/proc/%d/status", r.Process.Pid)

  // Check if the file exists (Linux-specific)
  if _, err := os.Stat(procFile); os.IsNotExist(err) {
    // For non-Linux systems, make a best-effort attempt using ps
    cmd := exec.Command("ps", "-o", "rss=", "-p", fmt.Sprintf("%d", r.Process.Pid))
    output, err := cmd.Output()
    if err != nil {
      return 0, fmt.Errorf("failed to get memory usage with ps: %v", err)
    }

    var rssKB uint64
    _, err = fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &rssKB)
    if err != nil {
      return 0, fmt.Errorf("failed to parse ps output: %v", err)
    }

    return rssKB / 1024, nil // Convert KB to MB
  }

  // Linux-specific implementation using /proc filesystem
  data, err := os.ReadFile(procFile)
  if err != nil {
    return 0, err
  }

  // Parse the file to find memory usage (VmRSS)
  lines := strings.Split(string(data), "\n")
  for _, line := range lines {
    if strings.HasPrefix(line, "VmRSS:") {
      var memKB uint64
      _, err := fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "VmRSS:")), "%d kB", &memKB)
      if err != nil {
        return 0, fmt.Errorf("failed to parse memory usage: %v", err)
      }
      return memKB / 1024, nil // Convert KB to MB
    }
  }

  return 0, fmt.Errorf("couldn't find memory usage information")
}

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
  fmt.Println("Executing RustHound-CE with arguments:", strings.Join(argsToPass, " "))

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

  // Set up resource monitoring if enabled
  var monitor *ResourceMonitor
  if *monitoringEnabled {
    monitor = NewResourceMonitor(*minDiskSpace, *maxMemory, *checkInterval, outputDir, cmd.Process)
    monitor.StartMonitoring()
  }

  // Wait for the command to complete
  err = cmd.Wait()

  // Stop monitoring
  if *monitoringEnabled && monitor != nil {
    monitor.Stop()
  }

  // Check if process was terminated due to resource constraints
  if err != nil {
    if _, ok := err.(*exec.ExitError); ok {
      fmt.Fprintf(os.Stderr, "RustHound-CE exited with an error: %v\n", err)
    } else {
      fmt.Fprintf(os.Stderr, "Error executing RustHound-CE: %v\n", err)
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
