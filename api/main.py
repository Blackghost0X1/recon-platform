from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from core.database import SessionLocal
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.orm import Session
from core.database import get_db, init_db
from core.models import Target, Subdomain, Endpoint, JSFile, Technology
from workers.engine import run_target_pipeline
import os
import shutil

# تهيئة قاعدة البيانات والجداول تلقائياً عند بدء تشغيل الـ API
init_db()

app = FastAPI(
    title="Recon & Monitoring Platform for Bug Hunting",
    description="Automated multi-tool reconnaissance pipeline with strict target isolation.",
    version="1.0.0"
)

# إعداد مجلدات الـ Templates والـ Static للواجهة
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/")
def read_root():
    return {"status": "online", "message": "Recon platform API is running successfully."}


@app.get("/dashboard", response_class=HTMLResponse)
def web_dashboard(request: Request, db: Session = Depends(get_db)):
    """عرض لوحة التحكم الرئيسية"""
    targets = db.query(Target).all()
    return templates.TemplateResponse(request, "index.html", {"targets": targets})


@app.post("/targets/add")
def add_target(domain: str, force_rescan: bool = False, background_tasks: BackgroundTasks = None, db: Session = Depends(get_db)):
    """
    إضافة هدف جديد مع خيار إعادة الفحص الإجباري (force_rescan=true/false)
    """
    domain = domain.strip().lower()
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain name.")

    existing_target = db.query(Target).filter_by(domain=domain).first()
    if existing_target:
        existing_target.status = "running"
        db.commit()
        target_id = existing_target.id
    else:
        new_target = Target(domain=domain, status="running")
        db.add(new_target)
        db.commit()
        db.refresh(new_target)
        target_id = new_target.id

    # تمرير متغير force_rescan للبايبلاين في الخلفية
    background_tasks.add_task(run_target_pipeline, domain, force_rescan)

    return {
        "message": f"Target '{domain}' pipeline started (Force Rescan: {force_rescan}).",
        "target_id": target_id,
        "domain": domain
    }


@app.get("/targets")
def list_targets(db: Session = Depends(get_db)):
    """استعراض كافة الأهداف المسجلة وحالتها الحالية"""
    targets = db.query(Target).all()
    result = []
    for t in targets:
        result.append({
            "id": t.id,
            "domain": t.domain,
            "status": t.status,
            "created_at": t.created_at,
            "subdomains_count": len(t.subdomains),
            "endpoints_count": len(t.endpoints),
            "js_files_count": len(t.js_files)
        })
    return {"targets": result}


@app.get("/targets/{target_id}/subdomains")
def get_target_subdomains(target_id: int, db: Session = Depends(get_db)):
    """استعراض السب دومينات الخاصة بهدف معين حصرياً"""
    target = db.query(Target).filter_by(id=target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    subs = db.query(Subdomain).filter_by(target_id=target_id).all()
    sub_list = [{"id": s.id, "subdomain": s.subdomain, "first_seen": s.first_seen} for s in subs]
    
    return {"target": target.domain, "total": len(sub_list), "subdomains": sub_list}


@app.get("/targets/{target_id}/endpoints")
def get_target_endpoints(target_id: int, db: Session = Depends(get_db)):
    """استعراض الـ Endpoints والروابط المسحوبة لهدف معين حصرياً"""
    target = db.query(Target).filter_by(id=target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    endpoints = db.query(Endpoint).filter_by(target_id=target_id).all()
    ep_list = [{"id": e.id, "url": e.url, "first_seen": e.first_seen} for e in endpoints]
    
    return {"target": target.domain, "total": len(ep_list), "endpoints": ep_list}


@app.get("/targets/{target_id}/js")
def get_target_js(target_id: int, db: Session = Depends(get_db)):
    """استعراض ملفات الـ JavaScript الخاصة بهدف معين حصرياً"""
    target = db.query(Target).filter_by(id=target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found.")

    js_files = db.query(JSFile).filter_by(target_id=target_id).all()
    js_list = [{"id": j.id, "js_url": j.js_url, "first_seen": j.first_seen} for j in js_files]
    
    return {"target": target.domain, "total": len(js_list), "js_files": js_list}


# ==========================================
# الإضافات الجديدة: التصدير (Export) والحذف (Delete)
# ==========================================

@app.get("/targets/{target_id}/export/{file_type}")
def export_target_file(target_id: int, file_type: str, db: Session = Depends(get_db)):
    """تصدير ملفات النطاقات الفرعية (subdomains) أو المضيفة (live) كملف نصي مباشر"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    base_dir = os.path.join("storage", "targets", target.domain, "raw")
    if file_type == "subdomains":
        file_path = os.path.join(base_dir, "subdomains.txt")
    elif file_type == "live":
        file_path = os.path.join(base_dir, "live_hosts.txt")
    else:
        raise HTTPException(status_code=400, detail="Invalid file type")
        
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="text/plain", filename=f"{target.domain}_{file_type}.txt")
    
    raise HTTPException(status_code=404, detail="File not found or recon not finished yet")


@app.delete("/targets/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    """حذف الهدف بالكامل من قاعدة البيانات ومن مجلدات التخزين المرتبطة به"""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # حذف مجلد التخزين بالكامل الخاص بالهدف
    target_folder = os.path.join("storage", "targets", target.domain)
    if os.path.exists(target_folder):
        shutil.rmtree(target_folder)
        
    # حذف الهدف من قاعدة البيانات (مع الحذف المتسلسل للبيانات المرتبطة)
    db.delete(target)
    db.commit()
    
    return {"status": "success", "message": f"Target {target.domain} deleted successfully."}

# (تأكد أن هذا المسار موجود ضمن ملف الـ FastAPI لديك)
@app.get("/api/targets/status")
def get_targets_status():
    db = SessionLocal()
    try:
        targets = db.query(Target).all()
        data = []
        for t in targets:
            data.append({
                "id": t.id,
                "domain": t.domain,
                "status": t.status,
                "stage": t.stage if t.stage else "Idle",
                "subdomains_count": len(t.subdomains),
                "endpoints_count": len(t.endpoints),
                "js_count": len(t.js_files)
            })
        return data
    finally:
        db.close()