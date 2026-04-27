import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import Base, engine
from routers import auth, targets, keys, scan_results, installers, dashboard, policy, reports

app = FastAPI(title="AUNIX - SSH Key Audit API")

# Allow the frontend origin (or origins, comma-separated) from env.
origins_raw = os.getenv(
    "CORS_ORIGINS",
    "http://127.0.0.1:5500,http://localhost:5500"
)
origins = [o.strip() for o in origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auto-create tables on startup. For production with migrations, replace
# this with Alembic. For a capstone deploy, this is fine.
Base.metadata.create_all(bind=engine)

app.include_router(auth.router, prefix="/api")
app.include_router(targets.router, prefix="/api")
app.include_router(keys.router, prefix="/api")
app.include_router(scan_results.router, prefix="/api")
app.include_router(installers.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(policy.router, prefix="/api")
app.include_router(reports.router, prefix="/api")


@app.get("/")
def root():
    return {"message": "AUNIX API is running", "docs": "/docs"}


@app.get("/healthz")
def healthz():
    return {"ok": True}
