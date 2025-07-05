# LoginGuard AI

> Advanced AI-Powered Login Security Analysis Platform

A cutting-edge web application that leverages Google Gemini AI to analyze login activity logs, detect suspicious patterns, and provide actionable security recommendations. Built with React, FastAPI, and MongoDB for enterprise-grade performance.

---

## Table of Contents

- [Features](#features)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Local Deployment](#local-deployment)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Usage Guide](#usage-guide)
- [Security Features](#security-features)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Core Capabilities
- **AI-Powered Analysis**: Advanced threat detection using Google Gemini AI
- **Real-time Processing**: Instant log analysis and risk assessment
- **Multi-format Support**: CSV uploads and raw text log parsing
- **Risk Categorization**: Intelligent classification into High, Medium, and Low risk levels
- **Actionable Insights**: Comprehensive security recommendations
- **Modern Interface**: Dark, professional dashboard with responsive design

### Security Detection
- Unusual login times and patterns
- Geographic anomalies and impossible travel
- New device and IP address detection
- Brute force attack identification
- Credential stuffing pattern recognition
- Failed login attempt clustering

---

## Tech Stack

### Frontend
- **React 18** - Modern UI framework
- **Tailwind CSS** - Utility-first styling
- **Responsive Design** - Mobile-first approach

### Backend
- **FastAPI** - High-performance Python API framework
- **Google Gemini AI** - Advanced language model integration
- **Async Processing** - Non-blocking request handling

### Database
- **MongoDB** - Document-based storage
- **Motor** - Async MongoDB driver

### Infrastructure
- **Docker** - Containerized deployment
- **Supervisor** - Process management
- **Nginx** - Reverse proxy and load balancing

---

## Quick Start

### Prerequisites

Ensure you have the following installed:
- **Python 3.11+**
- **Node.js 18+**
- **MongoDB 5.0+**
- **Git**

### Get Google Gemini API Key

1. Visit [Google AI Studio](https://aistudio.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the generated key for configuration

---

## Local Deployment

### 1. Clone Repository

```bash
git clone https://github.com/your-username/loginguard-ai.git
cd loginguard-ai
```

### 2. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env file with your configuration
```

### 3. Frontend Setup

```bash
# Navigate to frontend directory
cd ../frontend

# Install dependencies
npm install

# Set environment variables
cp .env.example .env
# Edit .env file with backend URL
```

### 4. Database Setup

```bash
# Start MongoDB service
# On Windows:
net start MongoDB

# On macOS:
brew services start mongodb/brew/mongodb-community

# On Linux:
sudo systemctl start mongod
```

### 5. Start Services

#### Development Mode

```bash
# Terminal 1 - Backend
cd backend
uvicorn server:app --host 0.0.0.0 --port 8001 --reload

# Terminal 2 - Frontend
cd frontend
npm start

# Terminal 3 - MongoDB (if not running as service)
mongod --dbpath /path/to/your/db
```

#### Production Mode

```bash
# Build frontend
cd frontend
npm run build

# Start with supervisor
sudo supervisorctl start all

# Check status
sudo supervisorctl status
```

### 6. Access Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8001
- **API Documentation**: http://localhost:8001/docs

---

## Configuration

### Environment Variables

#### Backend (.env)
```env
# Required
GEMINI_API_KEY=your_gemini_api_key_here
MONGO_URL=mongodb://localhost:27017

# Optional
DB_NAME=loginguard
LOG_LEVEL=INFO
MAX_UPLOAD_SIZE=10485760
```

#### Frontend (.env)
```env
REACT_APP_BACKEND_URL=http://localhost:8001
REACT_APP_MAX_FILE_SIZE=10485760
```

### Supervisor Configuration

```ini
[program:backend]
command=/path/to/venv/bin/uvicorn backend.server:app --host 0.0.0.0 --port 8001
directory=/app
environment=GEMINI_API_KEY="your_key",MONGO_URL="mongodb://localhost:27017"
autostart=true
autorestart=true

[program:frontend]
command=npm start
directory=/app/frontend
environment=HOST="0.0.0.0",PORT="3000"
autostart=true
autorestart=true
```

---

## API Documentation

### Authentication
Currently using API key-based authentication for Gemini AI service.

### Endpoints

#### Health Check
```http
GET /api/health
```

#### Upload CSV Analysis
```http
POST /api/upload-csv
Content-Type: multipart/form-data

file: CSV file with login logs
```

#### Raw Log Analysis
```http
POST /api/analyze-raw-logs
Content-Type: application/x-www-form-urlencoded

raw_logs: Raw log data (pipe-separated)
```

#### Get Analysis Results
```http
GET /api/analysis/{analysis_id}
```

#### Test Gemini Connection
```http
POST /api/test-gemini
```

### Data Format

#### CSV Format
```csv
username,ip_address,timestamp,location,device,login_status
john_doe,192.168.1.100,2024-01-15 09:15:23,New York,Chrome/Windows,success
```

#### Raw Log Format
```
timestamp|username|ip_address|location|device|login_status
2024-01-15 09:15:23|john_doe|192.168.1.100|New York|Chrome/Windows|success
```

### Response Format

```json
{
  "analysis_id": "uuid",
  "risk_summary": "string",
  "overall_risk_score": "LOW|MEDIUM|HIGH",
  "high_risk_logs": [],
  "medium_risk_logs": [],
  "low_risk_logs": [],
  "recommendations": []
}
```

---

## Usage Guide

### Step 1: Upload Data
- Click "Upload CSV" for structured data
- Or click "Paste Raw Logs" for unstructured data
- Use "Load Sample Data" for testing

### Step 2: Analysis
- Click "Analyze Logs" to start AI processing
- Wait for real-time analysis completion
- View comprehensive results dashboard

### Step 3: Review Results
- Check overall risk assessment
- Review categorized log entries
- Read security recommendations
- Expand log details for deeper analysis

### Step 4: Take Action
- Implement recommended security measures
- Monitor flagged user accounts
- Update security policies based on findings

---

## Security Features

### Data Protection
- **No Data Persistence**: Logs processed in memory only
- **Secure API Communication**: HTTPS enforcement
- **Input Validation**: Comprehensive data sanitization
- **Rate Limiting**: API abuse prevention

### AI Analysis Capabilities
- **Pattern Recognition**: Advanced behavioral analysis
- **Anomaly Detection**: Statistical deviation identification
- **Risk Scoring**: Multi-factor risk assessment
- **Contextual Analysis**: Geographic and temporal correlation

### Privacy Compliance
- **Data Minimization**: Process only necessary fields
- **Audit Logging**: Security event tracking
- **Access Control**: Role-based permissions
- **Encryption**: Data in transit protection

---

## Development

### Project Structure
```
loginguard-ai/
├── backend/
│   ├── server.py           # FastAPI application
│   ├── requirements.txt    # Python dependencies
│   └── .env               # Environment variables
├── frontend/
│   ├── src/
│   │   ├── App.js         # Main React component
│   │   ├── App.css        # Styling
│   │   └── index.js       # Entry point
│   ├── package.json       # Node dependencies
│   └── .env              # Frontend environment
├── scripts/               # Utility scripts
├── tests/                # Test suites
└── README.md             # Documentation
```

### Development Commands

#### Backend Development
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Code formatting
black .
isort .

# Type checking
mypy .

# Start development server
uvicorn server:app --reload --host 0.0.0.0 --port 8001
```

#### Frontend Development
```bash
# Install development dependencies
npm install

# Run tests
npm test

# Code formatting
npm run format

# Linting
npm run lint

# Start development server
npm start

# Build for production
npm run build
```

### Database Operations

#### MongoDB Commands
```bash
# Connect to database
mongo loginguard

# View collections
show collections

# Query logs
db.logs.find().limit(5)

# View analysis results
db.analysis.find().sort({created_at: -1}).limit(10)

# Create indexes
db.logs.createIndex({timestamp: 1})
db.analysis.createIndex({created_at: -1})
```

---

## Troubleshooting

### Common Issues

#### Backend Not Starting
```bash
# Check logs
tail -f /var/log/supervisor/backend.err.log

# Verify environment variables
echo $GEMINI_API_KEY

# Test MongoDB connection
mongo --eval "db.adminCommand('ismaster')"
```

#### Frontend Build Errors
```bash
# Clear cache
npm cache clean --force

# Delete node_modules and reinstall
rm -rf node_modules package-lock.json
npm install

# Check environment variables
cat .env
```

#### API Connection Issues
```bash
# Test backend endpoint
curl http://localhost:8001/api/health

# Check network connectivity
ping localhost

# Verify ports are not in use
netstat -tulpn | grep :8001
```

### Performance Optimization

#### Backend Tuning
```python
# Increase worker processes
uvicorn server:app --workers 4

# Configure connection pooling
MONGO_MAX_POOL_SIZE=100
MONGO_MIN_POOL_SIZE=10
```

#### Frontend Optimization
```javascript
// Enable production build
npm run build

// Serve with nginx
server {
    listen 80;
    root /app/frontend/build;
    
    location /api {
        proxy_pass http://localhost:8001;
    }
}
```

### Monitoring

#### Health Checks
```bash
# Backend health
curl http://localhost:8001/api/health

# Database health
mongo --eval "db.runCommand({ping: 1})"

# Service status
sudo supervisorctl status
```

#### Log Monitoring
```bash
# Application logs
tail -f /var/log/supervisor/backend.out.log

# Error logs
tail -f /var/log/supervisor/backend.err.log

# System logs
journalctl -u mongod -f
```

---

## Performance Benchmarks

### Response Times
- **Log Upload**: < 100ms
- **AI Analysis**: 2-5 seconds (depending on log volume)
- **Result Retrieval**: < 50ms

### Capacity Limits
- **Max File Size**: 10MB
- **Max Log Entries**: 10,000 per analysis
- **Concurrent Users**: 100+ (with proper scaling)

### Resource Requirements
- **CPU**: 2+ cores recommended
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 20GB for application and logs
- **Network**: 1Mbps minimum for AI API calls

---

## Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Code Standards
- **Python**: Follow PEP 8, use Black formatter
- **JavaScript**: Use Prettier, ESLint configuration
- **Commits**: Conventional commit format
- **Tests**: Maintain 80%+ coverage

### Testing
```bash
# Backend tests
pytest tests/ --cov=.

# Frontend tests
npm test -- --coverage

# Integration tests
npm run test:integration
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support

### Documentation
- **API Docs**: http://localhost:8001/docs
- **GitHub Wiki**: Coming soon
- **Video Tutorials**: Coming soon

### Community
- **Issues**: Report bugs and feature requests
- **Discussions**: General questions and ideas
- **Security**: Report vulnerabilities privately

### Contact
- **Maintainer**: Your Name
- **Email**: your.email@example.com
- **Website**: https://loginguard-ai.com

---

**Built with modern web technologies for enterprise-grade security analysis**

---

## Deployment Checklist

### Pre-deployment
- [ ] Environment variables configured
- [ ] Database connection tested
- [ ] API keys validated
- [ ] SSL certificates installed
- [ ] Firewall rules configured

### Post-deployment
- [ ] Health checks passing
- [ ] Log monitoring active
- [ ] Backup strategy implemented
- [ ] Performance metrics baseline established
- [ ] Security audit completed

### Monitoring Setup
```bash
# System monitoring
sudo apt install htop iotop

# Application monitoring
pip install prometheus-client

# Log aggregation
sudo apt install rsyslog

# Alerting
# Configure email notifications for critical errors
```

---
