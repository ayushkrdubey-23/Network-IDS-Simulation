
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

# Allow the local React development server to access this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    return {
        "message": "Welcome to the Network IDS Simulation API",
        "documentation": "/docs",
        "health": "/api/health",
    }