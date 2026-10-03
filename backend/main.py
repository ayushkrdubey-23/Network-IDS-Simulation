
from fastapi import FastAPI

from backend.routes.alerts import router


app = FastAPI(
    title="Network Intrusion Detection System API",
    description=(
        "A defensive Network IDS simulation API "
        "for synthetic traffic analysis, alert management, "
        "and security incident investigation."
    ),
    version="1.0.0",
)


app.include_router(router)


@app.get("/")
def root():
    return {
        "message": "Welcome to the Network IDS Simulation API",
        "documentation": "/docs",
        "health": "/api/health",
    }