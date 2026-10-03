#!/bin/bash
#
# Setup script for SentinelScan Live Monitoring
#
# This script automates the setup of the live monitoring feature,
# including database schema creation, dependency installation, and
# initial configuration.
#

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKEND_DIR="$PROJECT_ROOT/ps4-malware-suite-dashboard/backend"
FRONTEND_DIR="$PROJECT_ROOT/ps4-malware-suite-dashboard/frontend"

echo "=========================================="
echo "SentinelScan Live Monitoring Setup"
echo "=========================================="
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Functions
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Step 1: Verify prerequisites
echo "Step 1: Verifying prerequisites..."

if ! command -v python3 &> /dev/null; then
    print_error "Python 3 not found. Please install Python 3.9+"
    exit 1
fi
print_status "Python 3 found"

if ! command -v redis-cli &> /dev/null; then
    print_warning "Redis CLI not found. Assuming Redis is available at localhost:6379"
else
    print_status "Redis CLI found"
fi

if ! command -v psql &> /dev/null; then
    print_warning "PostgreSQL CLI not found. Assuming PostgreSQL is available"
else
    print_status "PostgreSQL CLI found"
fi

if ! command -v node &> /dev/null; then
    print_error "Node.js not found. Please install Node.js 18+"
    exit 1
fi
print_status "Node.js found"

echo ""

# Step 2: Backend setup
echo "Step 2: Setting up backend..."

cd "$BACKEND_DIR"

# Create .env if not exists
if [ ! -f .env ]; then
    print_status "Creating .env file..."
    cat > .env << 'EOF'
# PostgreSQL
DATABASE_URL=postgresql://localhost/sentinelscan
DB_USER=sentinelscan
DB_PASSWORD=change_me
DB_HOST=localhost
DB_PORT=5432

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET=your_jwt_secret_here_change_in_production
JWT_ALGORITHM=HS256
JWT_EXPIRY_HOURS=24

# CORS
CORS_ORIGINS=http://localhost:5173,http://localhost:3000,http://localhost:8000

# Live Monitoring
ENABLE_LIVE_MONITORING=true
LIVE_EVENT_RETENTION_HOURS=1
LIVE_RISK_SCORE_UPDATE_INTERVAL_SEC=5
LIVE_ALERT_RULES_ENABLED=true
MAX_CONCURRENT_LIVE_CLIENTS=10

# Sandbox URLs
CAPE_SANDBOX_URL=http://localhost:8090
ANDROID_SANDBOX_URL=http://localhost:8091

# Third-party APIs
VIRUSTOTAL_API_KEY=
SHODAN_API_KEY=
MAXMIND_LICENSE_KEY=
EOF
    print_warning "Created .env with default values. Please configure:"
    echo "  - DATABASE_URL"
    echo "  - REDIS_URL"
    echo "  - JWT_SECRET"
    echo "  - Third-party API keys"
else
    print_status ".env file already exists"
fi

# Install dependencies
if [ -f requirements.txt ]; then
    print_status "Installing Python dependencies..."
    pip install -r requirements.txt > /dev/null 2>&1 || {
        print_error "Failed to install dependencies"
        exit 1
    }
else
    print_warning "requirements.txt not found, skipping pip install"
fi

echo ""

# Step 3: Database setup
echo "Step 3: Setting up database..."

print_status "Creating database tables..."
python3 << 'EOF'
import os
from sqlalchemy import create_engine
from app.models.db_models import Base

db_url = os.getenv("DATABASE_URL", "postgresql://localhost/sentinelscan")
engine = create_engine(db_url)

try:
    Base.metadata.create_all(engine)
    print("✓ Database tables created successfully")
except Exception as e:
    print(f"✗ Error creating tables: {e}")
    exit(1)
EOF

echo ""

# Step 4: Frontend setup
echo "Step 4: Setting up frontend..."

cd "$FRONTEND_DIR"

print_status "Installing npm dependencies..."
if npm install > /dev/null 2>&1; then
    print_status "npm dependencies installed"
else
    print_error "Failed to install npm dependencies"
    exit 1
fi

echo ""

# Step 5: Generate configuration
echo "Step 5: Generating configuration..."

cat > "$BACKEND_DIR/live_monitoring_config.json" << 'EOF'
{
  "sandbox_event_emitter": {
    "poll_interval_ms": 100,
    "batch_size": 50,
    "redis_stream_name": "analysis:{analysis_id}:events",
    "redis_stream_cap": 10000,
    "redis_ttl_seconds": 3600,
    "sandbox_api_timeout_sec": 10,
    "sandbox_api_max_retries": 3
  },
  "event_processor": {
    "consumer_batch_size": 10,
    "threat_intel_cache_ttl_sec": 86400
  },
  "risk_scoring": {
    "update_interval_sec": 5,
    "decay_factor": 0.98,
    "decay_interval_sec": 300,
    "hysteresis_margin": 0.05
  },
  "alert_engine": {
    "dedup_window_sec": 10,
    "critical_alert_throttle_sec": 1,
    "warning_alert_throttle_sec": 10,
    "info_alert_throttle_sec": 30
  },
  "ioc_extractor": {
    "confidence_thresholds": {
      "known_c2": 95,
      "network_event": 50,
      "api_argument": 60,
      "file_hash": 90
    }
  }
}
EOF

print_status "Configuration file generated"

echo ""

# Step 6: Create test data
echo "Step 6: Creating sample configuration..."

cat > "$BACKEND_DIR/sample_alerts.json" << 'EOF'
{
  "rules": [
    {
      "rule_id": "c2_connection",
      "name": "Known C2 Connection",
      "description": "Connection to known C2 server",
      "severity": "critical",
      "trigger_event_types": ["network"],
      "condition": "enrichment.known_c2 == true"
    },
    {
      "rule_id": "exfil_threshold",
      "name": "High-Volume Data Exfiltration",
      "description": "More than 10MB data sent in 1 minute",
      "severity": "warning",
      "trigger_event_types": ["network"],
      "condition": "event_data.bytes_sent > 10000000"
    },
    {
      "rule_id": "credential_theft",
      "name": "Credential Theft Detected",
      "description": "API calls indicating credential theft",
      "severity": "critical",
      "trigger_event_types": ["api"],
      "condition": "api_name in ['ReadProcessMemory', 'QueryRegistryValue', 'GetClipboardData']"
    }
  ]
}
EOF

print_status "Sample alert rules created"

echo ""

# Step 7: Verification
echo "Step 7: Verifying installation..."

cd "$BACKEND_DIR"

print_status "Backend directory: $BACKEND_DIR"
print_status "Frontend directory: $FRONTEND_DIR"

if [ -f .env ]; then
    print_status ".env file configured"
fi

if [ -f "live_monitoring_config.json" ]; then
    print_status "Live monitoring config created"
fi

if [ -d "$FRONTEND_DIR/node_modules" ]; then
    print_status "Frontend dependencies installed"
fi

echo ""

# Step 8: Display next steps
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Update .env with your configuration:"
echo "   - Database credentials"
echo "   - Redis URL"
echo "   - JWT secret"
echo "   - API keys"
echo ""
echo "2. Start Redis:"
echo "   redis-server"
echo ""
echo "3. Start PostgreSQL:"
echo "   # Already running or:"
echo "   sudo service postgresql start"
echo ""
echo "4. Start backend:"
echo "   cd $BACKEND_DIR"
echo "   uvicorn app.main:app --reload --port 8000"
echo ""
echo "5. Start frontend:"
echo "   cd $FRONTEND_DIR"
echo "   npm run dev"
echo ""
echo "6. Access dashboard:"
echo "   http://localhost:5173"
echo ""
echo "For more details, see IMPLEMENTATION_GUIDE.md"
echo "=========================================="

exit 0
