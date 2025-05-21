#!/bin/bash
# build.sh - Script to build and run the RustHound-CE Docker image

# Make sure wrapper.go exists
if [ ! -f "wrapper.go" ]; then
    echo "Error: wrapper.go file not found"
    exit 1
fi

# Build the Docker image
echo "Building Docker image..."
docker build -t rusthound-wrapper -f Dockerfile .

echo "Docker image built successfully."
echo ""
echo "To run RustHound-CE with the wrapper, use:"
echo "docker run --rm -v $(pwd)/output:/app/output rusthound-ce [RustHound-CE arguments]"
echo ""
echo "Example:"
echo "docker run --rm -v $(pwd)/output:/app/output rusthound-ce -u username -p password -d domain.local -o /app/output"
