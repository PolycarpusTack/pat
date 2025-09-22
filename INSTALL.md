# Pat Fortress Installation Guide

## 🚀 Quick Install

### One-Line Installers

**Linux/macOS:**
```bash
curl -sSL https://raw.githubusercontent.com/pat-fortress/pat-fortress/main/scripts/install.sh | bash
```

**Windows (PowerShell):**
```powershell
iwr -useb https://raw.githubusercontent.com/pat-fortress/pat-fortress/main/scripts/install.ps1 | iex
```

## 📦 Package Managers

### Homebrew (macOS)
```bash
brew tap pat-fortress/tap
brew install pat-fortress
```

### APT (Debian/Ubuntu)
```bash
# Download and install
wget https://github.com/pat-fortress/pat-fortress/releases/latest/download/pat-fortress_2.0.0_amd64.deb
sudo dpkg -i pat-fortress_2.0.0_amd64.deb

# Start service
sudo systemctl start pat-fortress
sudo systemctl enable pat-fortress  # Start on boot
```

### YUM/DNF (RHEL/CentOS/Fedora)
```bash
# Download and install
wget https://github.com/pat-fortress/pat-fortress/releases/latest/download/pat-fortress-2.0.0-1.x86_64.rpm
sudo rpm -i pat-fortress-2.0.0-1.x86_64.rpm

# Start service
sudo systemctl start pat-fortress
sudo systemctl enable pat-fortress  # Start on boot
```

### Snap (Universal Linux)
```bash
sudo snap install pat-fortress
```

### Scoop (Windows)
```powershell
scoop bucket add pat-fortress https://github.com/pat-fortress/scoop-bucket
scoop install pat-fortress
```

### Chocolatey (Windows)
```powershell
choco install pat-fortress
```

## 🐳 Docker

### Quick Start
```bash
# Run with default settings
docker run -d --name pat-fortress \
  -p 1025:1025 \
  -p 8025:8025 \
  patfortress/pat-fortress:latest

# Open web interface
open http://localhost:8025
```

### Docker Compose
```yaml
version: '3.8'
services:
  pat-fortress:
    image: patfortress/pat-fortress:latest
    ports:
      - "1025:1025"   # SMTP
      - "8025:8025"   # Web UI
    environment:
      - PAT_LOG_LEVEL=info
      - PAT_HOSTNAME=fortress.local
    restart: unless-stopped
```

### With AI Analysis
```bash
docker run -d --name pat-fortress \
  -p 1025:1025 \
  -p 8025:8025 \
  -e PAT_OPENAI_API_KEY=sk-your-key-here \
  patfortress/pat-fortress:latest
```

## 📥 Manual Installation

### Download Binary
1. Go to [Releases](https://github.com/pat-fortress/pat-fortress/releases/latest)
2. Download the binary for your platform:
   - **Linux x64**: `pat-fortress_2.0.0_linux_amd64`
   - **macOS x64**: `pat-fortress_2.0.0_darwin_amd64`
   - **macOS ARM**: `pat-fortress_2.0.0_darwin_arm64`
   - **Windows x64**: `pat-fortress_2.0.0_windows_amd64.exe`

### Make Executable (Linux/macOS)
```bash
chmod +x pat-fortress_*
sudo mv pat-fortress_* /usr/local/bin/pat-fortress
```

### Add to PATH (Windows)
1. Move `pat-fortress.exe` to a directory in your PATH
2. Or add the directory to your PATH environment variable

## ⚙️ Configuration

### Environment Variables
```bash
export PAT_SMTP_BIND_ADDR=0.0.0.0:1025    # SMTP server address
export PAT_HTTP_BIND_ADDR=0.0.0.0:8025    # Web interface address
export PAT_LOG_LEVEL=info                 # Log level
export PAT_HOSTNAME=fortress.local        # Server hostname

# AI Analysis (optional)
export PAT_OPENAI_API_KEY=sk-your-key     # OpenAI API key
export PAT_OPENAI_MODEL=gpt-3.5-turbo     # AI model
```

### Command Line Flags
```bash
pat-fortress \
  --smtp-bind-addr=0.0.0.0:1025 \
  --http-bind-addr=0.0.0.0:8025 \
  --log-level=info \
  --enable-ai=true \
  --openai-api-key=sk-your-key
```

### Configuration File
Create `/etc/pat-fortress/config.yaml`:
```yaml
smtp:
  bind_addr: "0.0.0.0:1025"
  hostname: "fortress.local"
  max_message_size: 10485760

http:
  bind_addr: "0.0.0.0:8025"
  enable_cors: true

logging:
  level: "info"

ai:
  enabled: true
  openai_api_key: "sk-your-key-here"
  openai_model: "gpt-3.5-turbo"
```

## 🔧 Development Installation

### From Source
```bash
# Prerequisites: Go 1.21+
git clone https://github.com/pat-fortress/pat-fortress.git
cd pat-fortress

# Build
go build -o pat-fortress .

# Run
./pat-fortress
```

### Development with Hot Reload
```bash
# Install air for hot reload
go install github.com/cosmtrek/air@latest

# Run with hot reload
air
```

## 🏢 Enterprise Installation

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pat-fortress
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pat-fortress
  template:
    metadata:
      labels:
        app: pat-fortress
    spec:
      containers:
      - name: pat-fortress
        image: patfortress/pat-fortress:latest
        ports:
        - containerPort: 1025
        - containerPort: 8025
        env:
        - name: PAT_LOG_LEVEL
          value: "info"
---
apiVersion: v1
kind: Service
metadata:
  name: pat-fortress-service
spec:
  selector:
    app: pat-fortress
  ports:
  - name: smtp
    port: 1025
    targetPort: 1025
  - name: http
    port: 8025
    targetPort: 8025
  type: LoadBalancer
```

### Systemd Service (Linux)
```ini
# /etc/systemd/system/pat-fortress.service
[Unit]
Description=Pat Fortress Email Testing Server
After=network.target

[Service]
Type=simple
User=pat-fortress
Group=pat-fortress
ExecStart=/usr/local/bin/pat-fortress
Restart=always
RestartSec=5
Environment=PAT_SMTP_BIND_ADDR=0.0.0.0:1025
Environment=PAT_HTTP_BIND_ADDR=0.0.0.0:8025
Environment=PAT_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable pat-fortress
sudo systemctl start pat-fortress
```

## 🔍 Verification

### Check Installation
```bash
# Check version
pat-fortress --version

# Check health
curl http://localhost:8025/api/v3/health

# Send test email
echo "Subject: Test Email" | nc localhost 1025
```

### Web Interface
1. Start Pat Fortress: `pat-fortress`
2. Open browser: `http://localhost:8025`
3. Send test email to `localhost:1025`
4. View captured email in web interface

## 🚨 Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Check what's using the port
sudo lsof -i :1025
sudo lsof -i :8025

# Use different ports
pat-fortress --smtp-bind-addr=0.0.0.0:2025 --http-bind-addr=0.0.0.0:9025
```

**Permission denied:**
```bash
# On Linux, ports < 1024 require root
sudo pat-fortress --smtp-bind-addr=0.0.0.0:25

# Or use higher ports (recommended)
pat-fortress --smtp-bind-addr=0.0.0.0:1025
```

**Binary not found:**
```bash
# Check PATH
echo $PATH

# Add to PATH
export PATH=$PATH:/usr/local/bin

# Or use full path
/usr/local/bin/pat-fortress
```

### Logs
```bash
# Enable debug logging
pat-fortress --log-level=debug

# Check systemd logs (Linux)
sudo journalctl -u pat-fortress -f

# Check Docker logs
docker logs pat-fortress
```

## 🔄 Updates

### Automatic Updates
```bash
# Re-run installer
curl -sSL https://raw.githubusercontent.com/pat-fortress/pat-fortress/main/scripts/install.sh | bash

# Or with package managers
brew upgrade pat-fortress           # Homebrew
sudo apt update && sudo apt upgrade pat-fortress  # APT
```

### Manual Updates
1. Download new binary from [Releases](https://github.com/pat-fortress/pat-fortress/releases)
2. Replace existing binary
3. Restart service

## 🗑️ Uninstallation

### Remove Binary
```bash
# Remove binary
sudo rm /usr/local/bin/pat-fortress

# Remove from PATH if manually added
```

### Package Managers
```bash
brew uninstall pat-fortress        # Homebrew
sudo apt remove pat-fortress       # APT
sudo rpm -e pat-fortress           # RPM
```

### Docker
```bash
docker stop pat-fortress
docker rm pat-fortress
docker rmi patfortress/pat-fortress
```

### Systemd Service
```bash
sudo systemctl stop pat-fortress
sudo systemctl disable pat-fortress
sudo rm /etc/systemd/system/pat-fortress.service
sudo systemctl daemon-reload
```

## 📞 Support

- 📖 **Documentation**: [README.md](README.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/pat-fortress/pat-fortress/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/pat-fortress/pat-fortress/discussions)
- 📧 **Email**: Open an issue for support

---

**Pat Fortress: Email testing that just works.** 📧