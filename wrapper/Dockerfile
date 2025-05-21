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

# Copy the Go wrapper source
WORKDIR /build
COPY wrapper.go .

# Build the Go wrapper
RUN go build -o rusthound-wrapper wrapper.go

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
COPY --from=go-builder /build/rusthound-wrapper /app/rusthound-wrapper

# Create output directory
RUN mkdir -p /app/output

# Set the entrypoint to the Go wrapper
ENTRYPOINT ["/app/rusthound-wrapper"]
