from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="Simple API Target", version="1.0.0")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/items")
def items(limit: int = Query(default=10, ge=1, le=100), q: str = ""):
    return {"limit": limit, "query": q, "items": []}


@app.get("/reflect")
def reflect(value: str = ""):
    return {"value": value}


@app.get("/sql")
def sql_like(id: str = "1"):
    if "'" in id or "or" in id.lower():
        return JSONResponse(
            status_code=500,
            content={"error": "database error: syntax error near input"},
        )
    return {"id": id, "record": None}
