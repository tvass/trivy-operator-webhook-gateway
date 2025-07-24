"""Lightweight Webhook Receiver for Trivy Operator (Postee is Deprecated).

This module provides a RESTful API service for handling vulnerability reports
from the Trivy Operator, storing raw scan results via webhook notifications.
"""

import json
import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

from fastapi import FastAPI, status, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# Configure logging to output to terminal
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


class VulnerabilityReportResponse(BaseModel):
    """Response model for vulnerability report processing."""

    status: str = Field(..., description="Processing status")
    message: str = Field(..., description="Status message")
    received_at: datetime = Field(..., description="Timestamp of receipt")
    report_id: str = Field(..., description="Unique identifier for the report")


# FastAPI application instance with metadata
app = FastAPI(
    title="Trivy Operator Webhook Gateway",
    description=(
        "A webhook gateway service for processing Trivy Operator vulnerability scan results. "
        "This service receives raw vulnerability reports from the Trivy Operator and stores them "
        "for further processing."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests and responses."""
    # Log request details
    logger.debug(f"Incoming request: {request.method} {request.url}")
    logger.debug(f"Headers: {dict(request.headers)}")
    
    
    # Process the request
    try:
        response = await call_next(request)
        logger.info(f"Response status: {response.status_code}")
        return response
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        raise


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Log validation errors."""
    logger.error(f"Validation error for {request.url}")
    logger.debug(f"Validation details: {exc.errors()}")
    logger.debug(f"Request body: {exc.body}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(exc.body)},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Log all unhandled exceptions."""
    logger.error(f"Unhandled exception for {request.url}: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error": str(exc)},
    )


@app.post(
    "/vulnerabilityreports",
    response_model=VulnerabilityReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Store Trivy Report",
    description="Receives and stores raw reports from Trivy Operator webhook (ConfigAuditReport, VulnerabilityReport, ExposedSecretReport, SbomReport)",
    tags=["Configuration Audit"],
)
def process_vulnerability_report(
    report_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Process incoming Trivy Operator reports.

    This endpoint receives raw reports from the Trivy Operator webhook and stores them.
    Accepted report types: ConfigAuditReport, VulnerabilityReport, ExposedSecretReport, SbomReport.

    Args:
        report_data: The raw JSON data from the ConfigAuditReport.

    Returns:
        Dict[str, Any]: Confirmation of report storage with relevant details.
    """
    logger.debug(f"Processing report of type: {report_data.get('kind')}")
    logger.debug(f"Received data: {json.dumps(report_data, indent=2)}")
    
    # Define accepted report types
    ACCEPTED_REPORT_TYPES = [
        "VulnerabilityReport",
        #"ConfigAuditReport",
        #"ClusterConfigAuditReport",
        #"RbacAssessmentReport",
        #"ClusterRbacAssessmentReport",
        #"ExposedSecretReport",
        #"ComplianceReport",
        #"ClusterComplianceReport",
        #"InfraAssessmentReport",
        #"ClusterInfraAssessmentReport",
        #"SbomReport",
    ]

    report_kind = report_data.get("kind")
    if report_kind not in ACCEPTED_REPORT_TYPES:
        logger.error(f"Invalid kind: expected one of {ACCEPTED_REPORT_TYPES}, got '{report_kind}'")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "rejected",
                "message": f"Invalid report type. Expected one of {ACCEPTED_REPORT_TYPES}, got '{report_kind}'",
                "received_at": datetime.utcnow().isoformat(),
            }
        )
    
    if not report_data.get("apiVersion") == "aquasecurity.github.io/v1alpha1":
        logger.error(f"Invalid apiVersion: expected 'aquasecurity.github.io/v1alpha1', got '{report_data.get('apiVersion')}'")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "rejected",
                "message": f"Invalid apiVersion. Expected 'aquasecurity.github.io/v1alpha1', got '{report_data.get('apiVersion')}'",
                "received_at": datetime.utcnow().isoformat(),
            }
        )
    
    metadata = report_data.get("metadata", {})
    if not metadata or not isinstance(metadata, dict):
        logger.error("Missing or invalid 'metadata' field")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "rejected",
                "message": "Missing or invalid 'metadata' field",
                "received_at": datetime.utcnow().isoformat(),
            }
        )
    
    if "uid" not in metadata:
        logger.error("Missing required metadata field: 'uid'")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "rejected",
                "message": "Missing required metadata field: 'uid'",
                "received_at": datetime.utcnow().isoformat(),
            }
        )
    

    uid = metadata["uid"]
    logger.debug(f"Processing report with UID: {uid}")
    
    base_dir = Path("/tmp/trivy-reports")
    base_dir.mkdir(exist_ok=True)
    
    unique_dir_name = str(uuid.uuid4())
    tmp_dir = base_dir / unique_dir_name
    tmp_dir.mkdir(exist_ok=True)
    logger.debug(f"Created unique directory: {tmp_dir}")
    
    filename = "report.json"
    filepath = tmp_dir / filename
    
    try:
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
        logger.debug(f"Successfully saved report to: {filepath}")
    except Exception as e:
        logger.error(f"Failed to save report to file: {e}")
        error_response = {
            "status": "failed",
            "message": f"Failed to store {report_kind}: {str(e)}",
            "received_at": datetime.utcnow().isoformat(),
            "report_id": uid,
        }
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response
        )
    
    response = {
        "status": "accepted",
        "message": f"{report_kind} stored successfully",
        "received_at": datetime.utcnow().isoformat(),
        "report_id": uid,
    }
    
    logger.info(f"Successfully processed {report_kind} with UID: {uid}")
    return response


if __name__ == "__main__":
    import uvicorn

    
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )