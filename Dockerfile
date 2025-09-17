# Multi-stage build for C++ Social Network application (Simplified version)

# Build stage
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    libpq-dev \
    libpqxx-dev \
    nlohmann-json3-dev \
    libboost-system-dev \
    libboost-thread-dev \
    libboost-filesystem-dev \
    libasio-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Download and install Crow framework deb package
RUN curl -L https://github.com/CrowCpp/Crow/releases/download/v1.2.1.2/Crow-1.2.1-Linux.deb -o /tmp/crow.deb && \
    dpkg -i /tmp/crow.deb && \
    rm /tmp/crow.deb

# Copy source code
COPY CMakeLists.txt .
COPY src/ src/
COPY include/ include/
COPY migrations/ migrations/

# Build the application
RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

# Runtime stage
FROM ubuntu:22.04 AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpq5 \
    libpqxx-6.4 \
    libstdc++6 \
    libboost-system1.74.0 \
    libboost-thread1.74.0 \
    libboost-filesystem1.74.0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app user for security
RUN useradd -r -s /bin/false appuser

# Create working directory
WORKDIR /app

# Copy built application
COPY --from=builder /app/build/social_network .

# Copy migrations
COPY --from=builder /app/migrations/ migrations/

# Change ownership
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["./social_network"]
