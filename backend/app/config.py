from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "Attack Chain & Root Cause Analysis System"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = True
    
    class Config:
        env_file = ".env"

settings = Settings()
