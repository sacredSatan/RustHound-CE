package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// This is a standalone test program for testing the compression functionality
func main() {
	// Skip prerequisites check for this test program
	fmt.Println("Testing compression functionality")
	testCompression()
}

func testCompression() {
	// Define output directory
	outputDir := "./output"
	debug := true

	// Check if output directory exists
	_, err := os.Stat(outputDir)
	if os.IsNotExist(err) {
		fmt.Printf("Output directory %s does not exist\n", outputDir)
		os.Exit(1)
	}

	// Process the output directory
	fmt.Printf("Processing output directory: %s\n", outputDir)
	summary, err := ProcessRustHoundOutput(outputDir, debug)
	if err != nil {
		fmt.Printf("Error during processing: %v\n", err)
		os.Exit(1)
	}

	// Print findings summary
	fmt.Printf("Found %d security issues\n", len(summary.SecurityFindings))
	for i, finding := range summary.SecurityFindings {
		fmt.Printf("%d) [%s] %s: %s (Severity: %s)\n",
			i+1, finding.Type, finding.Username, finding.Description, finding.Severity)
	}

	// Create summary file
	summaryPath := filepath.Join(outputDir, "summary.json")
	err = SaveSummaryToFile(summary, summaryPath)
	if err != nil {
		fmt.Printf("Error saving summary: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Summary saved to: %s\n", summaryPath)

	// Compress the output
	fmt.Println("\nCompressing output files and cleaning up...")
	err = CompressOutputAndCleanup(outputDir, debug)
	if err != nil {
		fmt.Printf("Error compressing output: %v\n", err)
		os.Exit(1)
	}

	// List files after compression
	fmt.Println("\nFiles after compression:")
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
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error listing files: %v\n", err)
		os.Exit(1)
	}
}
