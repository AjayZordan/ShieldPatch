# Minimal Linux sandbox
FROM ubuntu:22.04

# Disable interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Update base packages
RUN apt-get update && apt-get install -y \
    bash \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for safety
RUN useradd -m sandboxuser
USER sandboxuser

# Default working directory
WORKDIR /home/sandboxuser

# Default command
CMD ["bash"]