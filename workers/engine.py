import os
import json
from datetime import datetime
from core.database import SessionLocal
from core.models import Target, Subdomain, Technology, Endpoint, JSFile

# استيراد وحدات الاستطلاع والفحص التي أنشأناها
from modules.subdomains import enumerate_subdomains
from modules.resolver import resolve_and_fingerprint
from modules.crawler import run_crawler
from modules.vulnerability import run_nuclei_scanner

def setup_target_storage(domain: str) -> tuple[str, str]:
    """
    تطبيق مبدأ العزل التام: إنشاء المجلدات الخاصة بالهدف فقط
    storage/targets/{domain}/raw/
    storage/targets/{domain}/processed/
    """
    base_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "storage", "targets", domain)
    raw_dir = os.path.join(base_dir, "raw")
    processed_dir = os.path.join(base_dir, "processed")

    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(processed_dir, exist_ok=True)

    return raw_dir, processed_dir


def save_recon_data_to_db(target_id: int, raw_dir: str):
    """
    قراءة النتائج المخزنة في مجلد الـ raw المعزول وحفظها بشكل منظم داخل قاعدة بيانات SQLite
    """
    db = SessionLocal()
    try:
        # 1. حفظ السب دومينات
        subdomains_file = os.path.join(raw_dir, "subdomains.txt")
        if os.path.exists(subdomains_file):
            with open(subdomains_file, "r") as f:
                for line in f:
                    sub_name = line.strip()
                    if sub_name:
                        # التحقق إن لم تكن مضافة مسبقاً لنفس الهدف
                        exists = db.query(Subdomain).filter_by(target_id=target_id, subdomain=sub_name).first()
                        if not exists:
                            new_sub = Subdomain(target_id=target_id, subdomain=sub_name, is_new=True)
                            db.add(new_sub)
            db.commit()

        # 2. حفظ التقنيات (Technologies) والـ Live Hosts من ملف JSON الخاص بـ httpx
        live_json_file = os.path.join(raw_dir, "live_hosts.json")
        if os.path.exists(live_json_file):
            with open(live_json_file, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        host_url = data.get("url")
                        host_domain = data.get("input") or data.get("host")
                        
                        if host_domain:
                            sub_obj = db.query(Subdomain).filter_by(target_id=target_id, subdomain=host_domain.lower()).first()
                            if sub_obj and "technologies" in data:
                                techs = data["technologies"]
                                for tech in techs:
                                    tech_name = tech if isinstance(tech, str) else tech.get("name", str(tech))
                                    t_exists = db.query(Technology).filter_by(subdomain_id=sub_obj.id, tech_name=tech_name).first()
                                    if not t_exists:
                                        new_tech = Technology(subdomain_id=sub_obj.id, tech_name=tech_name)
                                        db.add(new_tech)
                    except json.JSONDecodeError:
                        continue
            db.commit()

        # 3. حفظ الـ Endpoints والـ URLs
        urls_file = os.path.join(raw_dir, "all_urls.txt")
        if os.path.exists(urls_file):
            with open(urls_file, "r") as f:
                for line in f:
                    url_val = line.strip()
                    if url_val:
                        e_exists = db.query(Endpoint).filter_by(target_id=target_id, url=url_val).first()
                        if not e_exists:
                            new_endpoint = Endpoint(target_id=target_id, url=url_val)
                            db.add(new_endpoint)
            db.commit()

        # 4. حفظ ملفات الـ JavaScript
        js_file = os.path.join(raw_dir, "js_files.txt")
        if os.path.exists(js_file):
            with open(js_file, "r") as f:
                for line in f:
                    js_url = line.strip()
                    if js_url:
                        j_exists = db.query(JSFile).filter_by(target_id=target_id, js_url=js_url).first()
                        if not j_exists:
                            new_js = JSFile(target_id=target_id, js_url=js_url)
                            db.add(new_js)
            db.commit()

        print(f"[+] All raw recon results successfully synced to database for target ID: {target_id}")

    except Exception as e:
        db.rollback()
        print(f"[-] Error syncing data to database: {e}")
    finally:
        db.close()


def run_target_pipeline(target_domain: str, force_rescan: bool = False):
    """
    تنفيذ خط العمليات (Pipeline) الكامل لهدف معين مع دعم إعادة الفحص الإجباري وتتبع المراحل (Stages)
    """
    print(f"\n==============================================")
    print(f"[*] Initializing Pipeline for Target: {target_domain} (Force Rescan: {force_rescan})")
    print(f"==============================================")

    db = SessionLocal()
    try:
        # تسجيل أو جلب الهدف من قاعدة البيانات وتعيين الحالة الأولية والمرحلة
        target_obj = db.query(Target).filter_by(domain=target_domain).first()
        if not target_obj:
            target_obj = Target(domain=target_domain, status="running", stage="Initializing")
            db.add(target_obj)
            db.commit()
            db.refresh(target_obj)
        else:
            target_obj.status = "running"
            target_obj.stage = "Initializing"
            db.commit()

        target_id = target_obj.id
    finally:
        db.close()

    # 1. إعداد مجلدات العزل الخاصة بالهدف
    raw_dir, processed_dir = setup_target_storage(target_domain)
    subdomains_file = os.path.join(raw_dir, "subdomains.txt")

    # تحديث المرحلة: Subdomain Enumeration
    db = SessionLocal()
    try:
        t = db.query(Target).filter_by(id=target_id).first()
        if t:
            t.stage = "Subdomain Enumeration"
            db.commit()
    finally:
        db.close()

    # 2. خطوة جمع النطاقات الفرعية (مع التحقق من الكاش بناءً على رغبة المستخدم)
    if not force_rescan and os.path.exists(subdomains_file) and os.path.getsize(subdomains_file) > 0:
        print(f"[+] Found existing subdomains cache for {target_domain}. Skipping slow enumeration tools (Subfinder/Amass)...")
    else:
        print(f"[*] Starting fresh multi-tool subdomain enumeration...")
        enumerate_subdomains(target_domain, raw_dir)

    # تحديث المرحلة: Live Host Probing
    db = SessionLocal()
    try:
        t = db.query(Target).filter_by(id=target_id).first()
        if t:
            t.stage = "Live Host Probing"
            db.commit()
    finally:
        db.close()

    # 3. خطوة الفحص الحي واستخراج التقنيات (Httpx Resolution)[cite: 1]
    resolve_and_fingerprint(raw_dir)

    # تحديث المرحلة: Crawling Endpoints
    db = SessionLocal()
    try:
        t = db.query(Target).filter_by(id=target_id).first()
        if t:
            t.stage = "Crawling Endpoints"
            db.commit()
    finally:
        db.close()

    # 4. خطوة الزحف وسحب الروابط والـ JS (Katana Crawling)[cite: 1]
    run_crawler(raw_dir)

    # تحديث المرحلة: Vulnerability Scanning (Nuclei)
    db = SessionLocal()
    try:
        t = db.query(Target).filter_by(id=target_id).first()
        if t:
            t.stage = "Vulnerability Scanning (Nuclei)"
            db.commit()
    finally:
        db.close()

    # 5. خطوة فحص الثغرات السريعة (Nuclei Scanning)[cite: 1]
    run_nuclei_scanner(raw_dir)

    # تحديث المرحلة: Syncing Database
    db = SessionLocal()
    try:
        t = db.query(Target).filter_by(id=target_id).first()
        if t:
            t.stage = "Syncing Database"
            db.commit()
    finally:
        db.close()

    # 6. حفظ ومزامنة النتائج النصية داخل قاعدة البيانات مع ربطها بالهدف[cite: 1]
    save_recon_data_to_db(target_id, raw_dir)

    # تحديث حالة الهدف إلى مكتمل والمرحلة إلى Finished
    db = SessionLocal()
    try:
        t_obj = db.query(Target).filter_by(id=target_id).first()
        if t_obj:
            t_obj.status = "finished"
            t_obj.stage = "Finished"
            db.commit()
    finally:
        db.close()

    print(f"[+] Pipeline finished successfully for target: {target_domain}\n")