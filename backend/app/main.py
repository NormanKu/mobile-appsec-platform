from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api.routes.health import router as health_router
from app.api.routes.projects import router as projects_router
from app.api.routes.scans import router as scans_router
from app.api.routes.upload import router as upload_router
from app.core.config import settings
from app.db import initialize_database
from app.errors.exceptions import UploadValidationError
from app.errors.handlers import (
    request_validation_exception_handler,
    upload_validation_exception_handler,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

limiter = Limiter(
    key_func=get_remote_address, default_limits=[settings.rate_limit_default]
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    initialize_database()
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", lifespan=lifespan)
app.state.limiter = limiter

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "Accept"],
)

app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(UploadValidationError, upload_validation_exception_handler)
app.add_exception_handler(RequestValidationError, request_validation_exception_handler)


app.include_router(health_router)
app.include_router(projects_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(upload_router, prefix="/api/v1")
