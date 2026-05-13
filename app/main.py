from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import os
from app.analyzer import DataFlowAnalyzer
from app.exporters import to_json, to_sarif

app = FastAPI(title="Vulnerability Insight Analyzer", version="1.0")

# Создаём папку static если нет
if not os.path.exists("static"):
    os.makedirs("static")

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

class AnalyzeRequest(BaseModel):
    code: str

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")

@app.post("/api/analyze")
async def analyze_code(req: AnalyzeRequest):
    if not req.code.strip():
        raise HTTPException(400, "Код не может быть пустым")
    try:
        analyzer = DataFlowAnalyzer(req.code)
        vulns = analyzer.analyze()
        return JSONResponse({"vulnerabilities": vulns})
    except SyntaxError as e:
        raise HTTPException(422, f"Ошибка синтаксиса Python: {e.msg} (строка {e.lineno})")
    except Exception as e:
        raise HTTPException(500, f"Внутренняя ошибка анализатора: {str(e)}")

@app.post("/api/export/json")
async def export_json(req: AnalyzeRequest):
    analyzer = DataFlowAnalyzer(req.code)
    vulns = analyzer.analyze()
    return JSONResponse({"report": to_json(vulns, "user_input.py")})

@app.post("/api/export/sarif")
async def export_sarif(req: AnalyzeRequest):
    analyzer = DataFlowAnalyzer(req.code)
    vulns = analyzer.analyze()
    return JSONResponse(to_sarif(vulns, "user_input.py"))