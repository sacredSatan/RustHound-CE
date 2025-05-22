#!/bin/bash
# build.sh - Script to build and run the RustHound-CE Docker image

# Make sure main.go exists
if [ ! -f "main.go" ]; then
    echo "Error: main.go file not found"
    exit 1
fi

# Build the Docker image
echo "Building Docker image..."
docker build -t permiso-ad-scanner -f Dockerfile .

echo "Docker image built successfully."
echo ""
echo "To run RustHound-CE with the wrapper, use:"
echo "docker run --rm -v $(pwd)/output:/app/output permiso-ad-scanner [RustHound-CE arguments]"
echo ""
echo "Example:"
echo "docker run --rm -v $(pwd)/output:/app/output permiso-ad-scanner --min-disk 1000 --max-memory 4096 -- -u username -p password -d domain.local -o /app/output"
