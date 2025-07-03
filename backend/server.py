from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import List, Optional
import os
import json
import csv
import io
import re
from datetime import datetime
import asyncio
from emergentintegrations.llm.chat import LlmChat, UserMessage
import uuid
from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient
import logging
import psutil
import tempfile
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="LogSentinel Lite API", version="1.0.0")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = AsyncIOMotorClient(MONGO_URL)
db = client.logsentinel
logs_collection = db.logs
analysis_collection = db.analysis

# Pydantic models
class LogEntry(BaseModel):
    username: str
    ip_address: str
    timestamp: str
    location: str
    device: str
    login_status: str
    
class LogAnalysisRequest(BaseModel):
    logs: List[LogEntry]
    
class LogAnalysisResponse(BaseModel):
    analysis_id: str
    risk_summary: str
    high_risk_logs: List[dict]
    medium_risk_logs: List[dict]
    low_risk_logs: List[dict]
    recommendations: List[str]
    overall_risk_score: str

# Gemini API configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY environment variable is required")

def parse_csv_logs(csv_content: str) -> List[LogEntry]:
    """Parse CSV content into LogEntry objects"""
    logs = []
    csv_reader = csv.DictReader(io.StringIO(csv_content))
    
    for row in csv_reader:
        try:
            log_entry = LogEntry(
                username=row.get('username', ''),
                ip_address=row.get('ip_address', ''),
                timestamp=row.get('timestamp', ''),
                location=row.get('location', ''),
                device=row.get('device', ''),
                login_status=row.get('login_status', 'success')
            )
            logs.append(log_entry)
        except Exception as e:
            logger.warning(f"Failed to parse row: {row}, error: {e}")
            continue
    
    return logs

def parse_raw_logs(raw_content: str) -> List[LogEntry]:
    """Parse raw text logs into LogEntry objects"""
    logs = []
    lines = raw_content.strip().split('\n')
    
    for line in lines:
        if not line.strip():
            continue
            
        try:
            # Try to extract common log patterns
            # Format: timestamp|username|ip|location|device|status
            parts = line.split('|')
            if len(parts) >= 6:
                log_entry = LogEntry(
                    timestamp=parts[0].strip(),
                    username=parts[1].strip(),
                    ip_address=parts[2].strip(),
                    location=parts[3].strip(),
                    device=parts[4].strip(),
                    login_status=parts[5].strip()
                )
                logs.append(log_entry)
        except Exception as e:
            logger.warning(f"Failed to parse line: {line}, error: {e}")
            continue
    
    return logs

async def analyze_logs_with_gemini(logs: List[LogEntry]) -> dict:
    """Analyze logs using Gemini API for anomaly detection"""
    try:
        # Create Gemini chat instance
        session_id = str(uuid.uuid4())
        chat = LlmChat(
            api_key=GEMINI_API_KEY,
            session_id=session_id,
            system_message="You are a cybersecurity expert specializing in login anomaly detection. Analyze login logs and identify suspicious patterns."
        ).with_model("gemini", "gemini-2.0-flash")
        
        # Prepare logs data for analysis
        logs_data = []
        for log in logs:
            logs_data.append({
                "username": log.username,
                "ip_address": log.ip_address,
                "timestamp": log.timestamp,
                "location": log.location,
                "device": log.device,
                "login_status": log.login_status
            })
        
        # Create analysis prompt
        analysis_prompt = f"""
        Analyze these login logs for security anomalies and suspicious patterns:

        {json.dumps(logs_data, indent=2)}

        Please provide a detailed analysis covering:

        1. **Risk Assessment**: Categorize each log entry as LOW, MEDIUM, or HIGH risk
        2. **Anomaly Detection**: Identify patterns like:
           - Unusual login times (late night/early morning)
           - New or unrecognized IP addresses
           - Login attempts from unexpected geographic locations
           - Multiple failed login attempts (brute force indicators)
           - Credential stuffing patterns
           - Unusual device/browser combinations

        3. **Overall Risk Summary**: Provide a general assessment of the security posture

        4. **Recommendations**: Suggest specific actions to mitigate identified risks

        Please respond in the following JSON format:
        {{
            "overall_risk_score": "LOW|MEDIUM|HIGH",
            "risk_summary": "Brief summary of findings",
            "log_analysis": [
                {{
                    "log_index": 0,
                    "username": "username",
                    "risk_level": "LOW|MEDIUM|HIGH",
                    "risk_factors": ["factor1", "factor2"],
                    "explanation": "Detailed explanation of why this is risky"
                }}
            ],
            "recommendations": ["recommendation1", "recommendation2"]
        }}
        """
        
        # Send message to Gemini
        user_message = UserMessage(text=analysis_prompt)
        response = await chat.send_message(user_message)
        
        # Parse JSON response
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                analysis_result = json.loads(json_match.group())
            else:
                # Fallback if JSON parsing fails
                analysis_result = {
                    "overall_risk_score": "MEDIUM",
                    "risk_summary": response[:200] + "..." if len(response) > 200 else response,
                    "log_analysis": [],
                    "recommendations": ["Review all login attempts", "Enable multi-factor authentication"]
                }
        except json.JSONDecodeError:
            # Fallback response
            analysis_result = {
                "overall_risk_score": "MEDIUM",
                "risk_summary": "Analysis completed but response format needs review",
                "log_analysis": [],
                "recommendations": ["Review all login attempts", "Enable multi-factor authentication"]
            }
        
        return analysis_result
        
    except Exception as e:
        logger.error(f"Error analyzing logs with Gemini: {e}")
        # Return fallback analysis
        return {
            "overall_risk_score": "MEDIUM",
            "risk_summary": f"Analysis error: {str(e)}",
            "log_analysis": [],
            "recommendations": ["Manual review required", "Check API configuration"]
        }

@app.get("/")
async def root():
    return {"message": "LogSentinel Lite API is running"}

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "service": "LogSentinel Lite"}

@app.post("/api/upload-csv")
async def upload_csv(file: UploadFile = File(...)):
    """Upload and analyze CSV log file"""
    try:
        # Read CSV file
        content = await file.read()
        csv_content = content.decode('utf-8')
        
        # Parse logs
        logs = parse_csv_logs(csv_content)
        
        if not logs:
            raise HTTPException(status_code=400, detail="No valid log entries found in CSV")
        
        # Analyze with Gemini
        analysis_result = await analyze_logs_with_gemini(logs)
        
        # Store analysis in database
        analysis_id = str(uuid.uuid4())
        analysis_doc = {
            "analysis_id": analysis_id,
            "created_at": datetime.utcnow(),
            "logs_count": len(logs),
            "analysis_result": analysis_result,
            "logs": [log.dict() for log in logs]
        }
        
        await analysis_collection.insert_one(analysis_doc)
        
        # Categorize logs by risk level
        high_risk_logs = []
        medium_risk_logs = []
        low_risk_logs = []
        
        for i, log in enumerate(logs):
            log_dict = log.dict()
            log_dict["log_index"] = i
            
            # Find corresponding analysis
            log_analysis = None
            for analysis in analysis_result.get("log_analysis", []):
                if analysis.get("log_index") == i:
                    log_analysis = analysis
                    break
            
            if log_analysis:
                risk_level = log_analysis.get("risk_level", "LOW")
                log_dict["risk_level"] = risk_level
                log_dict["risk_factors"] = log_analysis.get("risk_factors", [])
                log_dict["explanation"] = log_analysis.get("explanation", "")
            else:
                log_dict["risk_level"] = "LOW"
                log_dict["risk_factors"] = []
                log_dict["explanation"] = "No specific risks identified"
            
            # Categorize
            if log_dict["risk_level"] == "HIGH":
                high_risk_logs.append(log_dict)
            elif log_dict["risk_level"] == "MEDIUM":
                medium_risk_logs.append(log_dict)
            else:
                low_risk_logs.append(log_dict)
        
        response = LogAnalysisResponse(
            analysis_id=analysis_id,
            risk_summary=analysis_result.get("risk_summary", "Analysis completed"),
            high_risk_logs=high_risk_logs,
            medium_risk_logs=medium_risk_logs,
            low_risk_logs=low_risk_logs,
            recommendations=analysis_result.get("recommendations", []),
            overall_risk_score=analysis_result.get("overall_risk_score", "MEDIUM")
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing CSV upload: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")

@app.post("/api/analyze-raw-logs")
async def analyze_raw_logs(raw_logs: str = Form(...)):
    """Analyze raw text logs"""
    try:
        # Parse raw logs
        logs = parse_raw_logs(raw_logs)
        
        if not logs:
            raise HTTPException(status_code=400, detail="No valid log entries found in raw text")
        
        # Analyze with Gemini
        analysis_result = await analyze_logs_with_gemini(logs)
        
        # Store analysis in database
        analysis_id = str(uuid.uuid4())
        analysis_doc = {
            "analysis_id": analysis_id,
            "created_at": datetime.utcnow(),
            "logs_count": len(logs),
            "analysis_result": analysis_result,
            "logs": [log.dict() for log in logs]
        }
        
        await analysis_collection.insert_one(analysis_doc)
        
        # Categorize logs by risk level
        high_risk_logs = []
        medium_risk_logs = []
        low_risk_logs = []
        
        for i, log in enumerate(logs):
            log_dict = log.dict()
            log_dict["log_index"] = i
            
            # Find corresponding analysis
            log_analysis = None
            for analysis in analysis_result.get("log_analysis", []):
                if analysis.get("log_index") == i:
                    log_analysis = analysis
                    break
            
            if log_analysis:
                risk_level = log_analysis.get("risk_level", "LOW")
                log_dict["risk_level"] = risk_level
                log_dict["risk_factors"] = log_analysis.get("risk_factors", [])
                log_dict["explanation"] = log_analysis.get("explanation", "")
            else:
                log_dict["risk_level"] = "LOW"
                log_dict["risk_factors"] = []
                log_dict["explanation"] = "No specific risks identified"
            
            # Categorize
            if log_dict["risk_level"] == "HIGH":
                high_risk_logs.append(log_dict)
            elif log_dict["risk_level"] == "MEDIUM":
                medium_risk_logs.append(log_dict)
            else:
                low_risk_logs.append(log_dict)
        
        response = LogAnalysisResponse(
            analysis_id=analysis_id,
            risk_summary=analysis_result.get("risk_summary", "Analysis completed"),
            high_risk_logs=high_risk_logs,
            medium_risk_logs=medium_risk_logs,
            low_risk_logs=low_risk_logs,
            recommendations=analysis_result.get("recommendations", []),
            overall_risk_score=analysis_result.get("overall_risk_score", "MEDIUM")
        )
        
        return response
        
    except Exception as e:
        logger.error(f"Error processing raw logs: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing logs: {str(e)}")

@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get stored analysis by ID"""
    try:
        analysis = await analysis_collection.find_one({"analysis_id": analysis_id})
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Remove MongoDB _id field
        analysis.pop("_id", None)
        return analysis
        
    except Exception as e:
        logger.error(f"Error retrieving analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving analysis: {str(e)}")

@app.post("/api/test-gemini")
async def test_gemini():
    """Test Gemini API connectivity"""
    try:
        session_id = str(uuid.uuid4())
        chat = LlmChat(
            api_key=GEMINI_API_KEY,
            session_id=session_id,
            system_message="You are a helpful assistant."
        ).with_model("gemini", "gemini-2.0-flash")
        
        user_message = UserMessage(text="Say 'Gemini API is working correctly!' and nothing else.")
        response = await chat.send_message(user_message)
        
        return {"status": "success", "response": response}
        
    except Exception as e:
        logger.error(f"Gemini API test failed: {e}")
        return {"status": "error", "error": str(e)}

@app.post("/api/export-csv/{analysis_id}")
async def export_analysis_csv(analysis_id: str):
    """Export analysis results as CSV"""
    try:
        # Get analysis from database
        analysis = await analysis_collection.find_one({"analysis_id": analysis_id})
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv', newline='')
        
        # Create CSV writer
        writer = csv.writer(temp_file)
        
        # Write headers
        headers = [
            'Log_Number', 'Username', 'IP_Address', 'Timestamp', 'Location', 
            'Device', 'Login_Status', 'Risk_Level', 'Risk_Factors', 'Analysis_Explanation'
        ]
        writer.writerow(headers)
        
        # Write log data
        all_logs = (
            analysis['analysis_result'].get('high_risk_logs', []) +
            analysis['analysis_result'].get('medium_risk_logs', []) +
            analysis['analysis_result'].get('low_risk_logs', [])
        )
        
        for i, log_analysis in enumerate(analysis['analysis_result'].get('log_analysis', []), 1):
            # Find corresponding log
            log_data = None
            for log in analysis.get('logs', []):
                if analysis['logs'].index(log) == log_analysis.get('log_index', -1):
                    log_data = log
                    break
            
            if log_data:
                risk_factors = '; '.join(log_analysis.get('risk_factors', []))
                
                row = [
                    i,
                    log_data.get('username', ''),
                    log_data.get('ip_address', ''),
                    log_data.get('timestamp', ''),
                    log_data.get('location', ''),
                    log_data.get('device', ''),
                    log_data.get('login_status', ''),
                    log_analysis.get('risk_level', 'LOW'),
                    risk_factors,
                    log_analysis.get('explanation', '')
                ]
                writer.writerow(row)
        
        # Add summary information
        writer.writerow([])
        writer.writerow(['ANALYSIS SUMMARY'])
        writer.writerow(['Overall Risk Level', analysis['analysis_result'].get('overall_risk_score', 'UNKNOWN')])
        writer.writerow(['Risk Summary', analysis['analysis_result'].get('risk_summary', '')])
        writer.writerow(['Analysis Date', analysis.get('created_at', '').strftime('%Y-%m-%d %H:%M:%S') if analysis.get('created_at') else ''])
        
        # Add recommendations
        writer.writerow([])
        writer.writerow(['SECURITY RECOMMENDATIONS'])
        for i, rec in enumerate(analysis['analysis_result'].get('recommendations', []), 1):
            writer.writerow([f'Recommendation {i}', rec])
        
        temp_file.close()
        
        # Return file
        return FileResponse(
            temp_file.name,
            media_type='text/csv',
            filename=f'loginguard_analysis_{analysis_id[:8]}.csv'
        )
        
    except Exception as e:
        logger.error(f"Error exporting CSV: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting CSV: {str(e)}")

@app.post("/api/export-pdf/{analysis_id}")
async def export_analysis_pdf(analysis_id: str):
    """Export analysis results as PDF"""
    try:
        # Get analysis from database
        analysis = await analysis_collection.find_one({"analysis_id": analysis_id})
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        # Create temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_file.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(temp_file.name, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=1,  # Center alignment
            textColor=colors.darkblue
        )
        story.append(Paragraph("LoginGuard AI Security Analysis Report", title_style))
        story.append(Spacer(1, 20))
        
        # Analysis Info
        info_data = [
            ['Analysis ID:', analysis_id],
            ['Analysis Date:', analysis.get('created_at', '').strftime('%Y-%m-%d %H:%M:%S') if analysis.get('created_at') else 'Unknown'],
            ['Total Logs Analyzed:', str(analysis.get('logs_count', 0))],
            ['Overall Risk Level:', analysis['analysis_result'].get('overall_risk_score', 'UNKNOWN')]
        ]
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(info_table)
        story.append(Spacer(1, 20))
        
        # Risk Summary
        story.append(Paragraph("Risk Assessment Summary", styles['Heading2']))
        story.append(Paragraph(analysis['analysis_result'].get('risk_summary', 'No summary available'), styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Risk Statistics
        high_count = len(analysis['analysis_result'].get('high_risk_logs', []))
        medium_count = len(analysis['analysis_result'].get('medium_risk_logs', []))
        low_count = len(analysis['analysis_result'].get('low_risk_logs', []))
        
        risk_data = [
            ['Risk Level', 'Count', 'Percentage'],
            ['High Risk', str(high_count), f"{(high_count/analysis.get('logs_count', 1)*100):.1f}%"],
            ['Medium Risk', str(medium_count), f"{(medium_count/analysis.get('logs_count', 1)*100):.1f}%"],
            ['Low Risk', str(low_count), f"{(low_count/analysis.get('logs_count', 1)*100):.1f}%"]
        ]
        
        risk_table = Table(risk_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 20))
        
        # Security Recommendations
        story.append(Paragraph("Security Recommendations", styles['Heading2']))
        for i, rec in enumerate(analysis['analysis_result'].get('recommendations', []), 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
            story.append(Spacer(1, 10))
        
        story.append(Spacer(1, 20))
        
        # High Risk Logs Detail
        if high_count > 0:
            story.append(Paragraph("High Risk Logs Details", styles['Heading2']))
            
            for i, log_analysis in enumerate(analysis['analysis_result'].get('log_analysis', [])):
                if log_analysis.get('risk_level') == 'HIGH':
                    # Find corresponding log
                    log_data = None
                    for log in analysis.get('logs', []):
                        if analysis['logs'].index(log) == log_analysis.get('log_index', -1):
                            log_data = log
                            break
                    
                    if log_data:
                        story.append(Paragraph(f"Log #{i+1}: {log_data.get('username', 'Unknown')}", styles['Heading3']))
                        
                        log_details = [
                            ['Field', 'Value'],
                            ['Username', log_data.get('username', '')],
                            ['IP Address', log_data.get('ip_address', '')],
                            ['Timestamp', log_data.get('timestamp', '')],
                            ['Location', log_data.get('location', '')],
                            ['Device', log_data.get('device', '')],
                            ['Status', log_data.get('login_status', '')],
                            ['Risk Factors', '; '.join(log_analysis.get('risk_factors', []))]
                        ]
                        
                        log_table = Table(log_details, colWidths=[1.5*inch, 4*inch])
                        log_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.mistyrose),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))
                        story.append(log_table)
                        story.append(Spacer(1, 15))
        
        # Footer
        story.append(Spacer(1, 30))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=10,
            alignment=1,
            textColor=colors.grey
        )
        story.append(Paragraph("Generated by LoginGuard AI - Advanced Login Security Analysis", footer_style))
        
        # Build PDF
        doc.build(story)
        
        # Return file
        return FileResponse(
            temp_file.name,
            media_type='application/pdf',
            filename=f'loginguard_analysis_{analysis_id[:8]}.pdf'
        )
        
    except Exception as e:
        logger.error(f"Error exporting PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error exporting PDF: {str(e)}")

@app.get("/api/health-dashboard")
async def health_dashboard():
    """Get comprehensive system health information"""
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Database health
        db_healthy = True
        db_status = "Connected"
        try:
            # Test database connection
            await db.command("ping")
        except Exception as e:
            db_healthy = False
            db_status = f"Error: {str(e)}"
        
        # Gemini API health
        gemini_healthy = True
        gemini_status = "Connected"
        try:
            session_id = str(uuid.uuid4())
            chat = LlmChat(
                api_key=GEMINI_API_KEY,
                session_id=session_id,
                system_message="You are a helpful assistant."
            ).with_model("gemini", "gemini-2.0-flash")
            
            user_message = UserMessage(text="Health check")
            await chat.send_message(user_message)
        except Exception as e:
            gemini_healthy = False
            gemini_status = f"Error: {str(e)}"
        
        # Get recent analysis stats
        recent_analyses = await analysis_collection.count_documents({
            "created_at": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)}
        })
        
        total_analyses = await analysis_collection.count_documents({})
        
        # Service uptime (approximate)
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        health_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": "healthy" if db_healthy and gemini_healthy else "degraded",
            "system_metrics": {
                "cpu_usage_percent": cpu_percent,
                "memory_usage_percent": memory.percent,
                "memory_used_gb": round(memory.used / (1024**3), 2),
                "memory_total_gb": round(memory.total / (1024**3), 2),
                "disk_usage_percent": disk.percent,
                "disk_used_gb": round(disk.used / (1024**3), 2),
                "disk_total_gb": round(disk.total / (1024**3), 2),
                "uptime_hours": round(uptime.total_seconds() / 3600, 1)
            },
            "services": {
                "database": {
                    "status": db_status,
                    "healthy": db_healthy
                },
                "gemini_ai": {
                    "status": gemini_status,
                    "healthy": gemini_healthy
                }
            },
            "analytics": {
                "analyses_today": recent_analyses,
                "total_analyses": total_analyses
            },
            "alerts": []
        }
        
        # Add alerts based on thresholds
        if cpu_percent > 80:
            health_data["alerts"].append({
                "type": "warning",
                "message": f"High CPU usage: {cpu_percent}%"
            })
        
        if memory.percent > 85:
            health_data["alerts"].append({
                "type": "warning", 
                "message": f"High memory usage: {memory.percent}%"
            })
        
        if disk.percent > 90:
            health_data["alerts"].append({
                "type": "critical",
                "message": f"High disk usage: {disk.percent}%"
            })
        
        if not db_healthy:
            health_data["alerts"].append({
                "type": "critical",
                "message": "Database connection failed"
            })
        
        if not gemini_healthy:
            health_data["alerts"].append({
                "type": "critical",
                "message": "Gemini AI service unavailable"
            })
        
        return health_data
        
    except Exception as e:
        logger.error(f"Error getting health dashboard: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting health dashboard: {str(e)}")

@app.get("/api/sample-files")
async def get_sample_files():
    """Get list of available sample log files"""
    try:
        sample_dir = "/app/sample_data"
        sample_files = []
        
        if os.path.exists(sample_dir):
            for filename in os.listdir(sample_dir):
                if filename.endswith('.csv'):
                    file_path = os.path.join(sample_dir, filename)
                    file_size = os.path.getsize(file_path)
                    
                    # Count lines in file
                    with open(file_path, 'r') as f:
                        line_count = sum(1 for line in f) - 1  # Subtract header
                    
                    sample_files.append({
                        "filename": filename,
                        "display_name": filename.replace('_', ' ').replace('.csv', '').title(),
                        "size_bytes": file_size,
                        "log_count": line_count
                    })
        
        return {"sample_files": sample_files}
        
    except Exception as e:
        logger.error(f"Error getting sample files: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting sample files: {str(e)}")

@app.get("/api/sample-file/{filename}")
async def download_sample_file(filename: str):
    """Download a specific sample file"""
    try:
        sample_dir = "/app/sample_data"
        file_path = os.path.join(sample_dir, filename)
        
        if not os.path.exists(file_path) or not filename.endswith('.csv'):
            raise HTTPException(status_code=404, detail="Sample file not found")
        
        return FileResponse(
            file_path,
            media_type='text/csv',
            filename=filename
        )
        
    except Exception as e:
        logger.error(f"Error downloading sample file: {e}")
        raise HTTPException(status_code=500, detail=f"Error downloading sample file: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)