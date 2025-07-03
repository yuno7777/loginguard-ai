from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)