from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes.health import router as health_router
from app.api.routes.upload import router as upload_router
from app.core.config import settings
from app.errors.exceptions import UploadValidationError
from app.errors.handlers import request_validation_exception_handler, upload_validation_exception_handler

app = FastAPI(title=settings.app_name, version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(UploadValidationError, upload_validation_exception_handler)
app.add_exception_handler(RequestValidationError, request_validation_exception_handler)

app.include_router(health_router)
app.include_router(upload_router, prefix="/api/v1")
