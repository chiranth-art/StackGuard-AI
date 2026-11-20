from fastapi import FastAPI

# Create our FastAPI application
app = FastAPI(
    title="StackGuard AI",
    description="Smart Software Dependency Risk Analyzer",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "message": "Welcome to StackGuard AI",
        "status": "Backend is running successfully"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "application": "StackGuard AI"
    }