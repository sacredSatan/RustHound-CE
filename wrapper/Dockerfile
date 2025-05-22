FROM rust:latest as rust-builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    make \
    pkg-config \
    libssl-dev \
    libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone the specific branch of RustHound-CE
WORKDIR /build
# ARG CACHEBUST=$(date +%s)
RUN git clone https://github.com/sacredSatan/RustHound-CE.git
WORKDIR /build/RustHound-CE

# Check the binary name that will be produced
RUN grep -r "name" Cargo.toml || true

# Build RustHound-CE
RUN cargo build --release

# Find the actual binary name
RUN find /build/RustHound-CE/target/release -type f -executable -not -name "*.d" -ls

# Go builder stage
FROM golang:1.20-buster as go-builder

# Create workdir and copy all Go wrapper source files
WORKDIR /build/wrapper
# Copy directly from the current directory (which is the wrapper directory)
COPY *.go ./

# Initialize a Go module and build the wrapper
RUN go mod init permiso-ad-scanner && \
    go mod tidy && \
    go build -o permiso-ad-scanner .

# Final stage - using bookworm (Debian 12) for newer GLIBC version
FROM debian:bookworm-slim

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    libkrb5-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy RustHound-CE binary - using reliable detection based on findings
COPY --from=rust-builder /build/RustHound-CE/target/release/rusthound-ce /app/rusthound-ce

# Copy Go wrapper from go-builder stage
COPY --from=go-builder /build/wrapper/permiso-ad-scanner /app/permiso-ad-scanner

# Create output directory
RUN mkdir -p /app/output

# Create an entrypoint script that handles help command
RUN echo '#!/bin/sh' > /app/entrypoint.sh && \
    echo 'if [ "$1" = "help" ]; then' >> /app/entrypoint.sh && \
    echo '  /app/permiso-ad-scanner --help' >> /app/entrypoint.sh && \
    echo 'else' >> /app/entrypoint.sh && \
    echo '  /app/permiso-ad-scanner "$@"' >> /app/entrypoint.sh && \
    echo 'fi' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Set the entrypoint to our script
ENTRYPOINT ["/app/entrypoint.sh"]
