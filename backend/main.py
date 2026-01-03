from scanner.explainer import generate_ai_explanation
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import shutil
import os
import uuid

from scanner.clamav import scan_clamav
from scanner.yara_scan import scan_yara
from scanner.static import static_analysis
from scanner.verdict import calculate_verdict
from scanner.report import generate_pdf_report

app = FastAPI(title="ShieldWatch Malware Detection API")

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    temp_filename = f"/tmp/{uuid.uuid4()}_{file.filename}"

    with open(temp_filename, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        clamav_result = scan_clamav(temp_filename)
        yara_result = scan_yara(temp_filename)
        static_result = static_analysis(temp_filename)

        verdict = calculate_verdict(
            clamav=clamav_result,
            yara=yara_result,
            static=static_result
        )

        # ✅ Correctly aligned AI explanation
        explanation = generate_ai_explanation({
            "final_verdict": verdict
        })

        return {
            "filename": file.filename,
            "clamav": clamav_result,
            "yara": yara_result,
            "static": static_result,
            "final_verdict": verdict,
            "ai_explanation": explanation
        }

    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)



@app.post("/report")
async def generate_report(file: UploadFile = File(...)):
    temp_filename = f"/tmp/{uuid.uuid4()}_{file.filename}"
    report_path = f"/tmp/{uuid.uuid4()}_report.pdf"

    with open(temp_filename, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        clamav_result = scan_clamav(temp_filename)
        yara_result = scan_yara(temp_filename)
        static_result = static_analysis(temp_filename)

        verdict = calculate_verdict(
            clamav=clamav_result,
            yara=yara_result,
            static=static_result
        )

        result = {
            "filename": file.filename,
            "clamav": clamav_result,
            "yara": yara_result,
            "static": static_result,
            "final_verdict": verdict
        }

        generate_pdf_report(result, report_path)

        return FileResponse(
            report_path,
            media_type="application/pdf",
            filename="ShieldWatch_Report.pdf"
        )

    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

