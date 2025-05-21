# RustHound Security Rules Test Tool

This is a simple testing tool for validating the security detection rules in the RustHound postprocessor. 
It allows you to quickly test a single JSON file for security findings without running the full RustHound workflow.

## Usage

```bash
go run analyze_json.go -file <path-to-json-file> [options]
```

### Options

- `-file <path>`: Path to the RustHound JSON file to analyze (required)
- `-dormant <days>`: Number of days of inactivity to consider an account dormant (default: 90)
- `-v`: Enable verbose output with detailed information
- `-output <path>`: Path to save results as JSON (optional)

### Examples

Basic usage:
```bash
go run analyze_json.go -file ../output/users.json
```

Test with 30-day dormant account threshold:
```bash
go run analyze_json.go -file ../output/users.json -dormant 30
```

Enable verbose output:
```bash
go run analyze_json.go -file ../output/users.json -v
```

Save results to a file:
```bash
go run analyze_json.go -file ../output/users.json -output findings.json
```

## How It Works

This tool:
1. Creates a temporary directory
2. Copies the specified JSON file to this directory
3. Calls the same `ProcessRustHoundOutput` function used by the main program
4. Displays the results

## Current Security Rules

The tool checks for the following security issues:

1. **Dormant accounts**: Active accounts with no activity in past X days (configurable with `-dormant` flag)
2. **Insecure guest accounts**: Guest accounts with the "password not required" flag set

## Note

To modify the dormant days threshold, you need to change the value in the wrapper package.
The current threshold is set to 1 day for testing purposes. 