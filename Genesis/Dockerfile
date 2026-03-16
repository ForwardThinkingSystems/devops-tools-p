# Extended OpenClaw image with security tools, browser, and memory plugin.
# Build: docker build -t openclaw-bot:latest .
FROM openclaw/openclaw:latest

# Switch to root for package installation
USER root

# Install Socket CLI for supply chain security scanning
RUN npm install -g @socketsecurity/cli

# Install Playwright + Chromium for native browser tool.
# --with-deps pulls required system libraries (libglib, libnss, etc.)
RUN npx playwright install --with-deps chromium

# Install Hindsight memory plugin (embedded PostgreSQL, no sidecar needed)
RUN npm install -g @vectorize-io/hindsight-openclaw

# Lock skills directory — no runtime skill installs permitted
RUN if [ -d /app/skills ]; then chmod -R 555 /app/skills; fi

# Switch back to non-root user
USER node
