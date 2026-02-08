import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api import reports, logs, analysis, scenarios, dev

app = FastAPI(
    title=settings.APP_NAME,
    description="API for Attack Chain & Root Cause Analysis System",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    debug=settings.DEBUG
)

# CORS Configuration
# In production, this should be set to specific domains via env vars
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"], # Limit methods to what is needed
    allow_headers=["*"],
)

# Include Routers
app.include_router(reports.router, prefix=f"{settings.API_V1_STR}", tags=["reports"])
app.include_router(logs.router, prefix=f"{settings.API_V1_STR}", tags=["logs"])
app.include_router(analysis.router, prefix=f"{settings.API_V1_STR}", tags=["analysis"])
app.include_router(scenarios.router, prefix=f"{settings.API_V1_STR}", tags=["scenarios"])
app.include_router(dev.router, prefix=f"{settings.API_V1_STR}", tags=["dev"])

@app.get("/", tags=["health"])
async def root():
    return {"message": "Attack Chain Analysis System API is running", "status": "healthy"}

@app.get("/health", tags=["health"])
async def health_check():
    return {"status": "healthy"}
