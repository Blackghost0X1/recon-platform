import time
import requests
from datetime import datetime
from sqlalchemy.orm import Session
from apscheduler.schedulers.background import BackgroundScheduler
from core.database import SessionLocal
from core.models import Target, Subdomain, Endpoint, JSFile, Alert

# إعدادات بوت التيليجرام
BOT_TOKEN = "8777767033:AAHG0-SWmyO9SC6FvmL8b95EZ9L1mukc3cA"
CHAT_ID = "5082216354"

def send_telegram_alert(message: str):
    """إرسال تنبيه فوري عبر بوت تيليجرام"""
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        if not response.ok:
            print(f"[ERROR] Failed to send Telegram alert: {response.text}")
    except Exception as e:
        print(f"[ERROR] Telegram connection error: {e}")

def process_recon_diff(target_id: int, new_subdomains: list, new_endpoints: list, new_js: list):
    """
    موتور مقارنة النتائج (Diff Engine) مع إرسال تنبيهات فورية لتيليجرام وحفظها بقاعدة البيانات.
    """
    db: Session = SessionLocal()
    try:
        target = db.query(Target).filter(Target.id == target_id).first()
        if not target:
            return

        # 1. مقارنة الـ Subdomains
        existing_subs = {s.subdomain for s in target.subdomains}
        new_subs_found = [sub for sub in new_subdomains if sub not in existing_subs]
        for sub in new_subs_found:
            db.add(Subdomain(target_id=target.id, subdomain=sub, is_new=True))

        # 2. مقارنة الـ Endpoints
        existing_ends = {e.url for e in target.endpoints}
        new_ends_found = []
        for endpoint in new_endpoints:
            url = endpoint.get("url") if isinstance(endpoint, dict) else endpoint
            if url and url not in existing_ends:
                new_ends_found.append(url)
                db.add(Endpoint(target_id=target.id, url=url, status_code=200, is_new=True))

        # 3. مقارنة الـ JS Files
        existing_js = {j.js_url for j in target.js_files}
        new_js_found = [js for js in new_js if js not in existing_js]
        for js in new_js_found:
            db.add(JSFile(target_id=target.id, js_url=js, is_new=True))

        # 4. إصدار تنبيهات وإرسالها عبر التيليجرام إذا وجدنا عناصر جديدة
        if new_subs_found or new_ends_found or new_js_found:
            alert_msg = f"🚨 *New Findings Alert for:* `{target.domain}`\n\n"
            if new_subs_found:
                alert_msg += f"🌐 *New Subdomains ({len(new_subs_found)}):*\n" + "\n".join([f"• `{s}`" for s in new_subs_found[:10]]) + "\n\n"
            if new_ends_found:
                alert_msg += f"⚡ *New Endpoints Found:* `{len(new_ends_found)}`\n"
            if new_js_found:
                alert_msg += f"📜 *New JS Files Found:* `{len(new_js_found)}`\n"

            # حفظ التنبيه في جدول الـ Alerts
            db.add(Alert(
                target_id=target.id,
                title=f"New Assets for {target.domain}",
                message=alert_msg,
                severity="warning"
            ))

            # إرسال الإشعار الفوري للبوت
            send_telegram_alert(alert_msg)

        target.last_scanned_at = datetime.utcnow()
        db.commit()

    except Exception as e:
        db.rollback()
        print(f"[ERROR] Diff engine failed: {e}")
    finally:
        db.close()

def scheduled_recon_job():
    """المهمة المجدولة: تقوم بالبحث عن الأهداف المفعل عليها المراقبة وإعادة فحصها"""
    db: Session = SessionLocal()
    try:
        monitored_targets = db.query(Target).filter(Target.is_monitored == True).all()
        for target in monitored_targets:
            print(f"[MONITORING] Running scheduled scan for target: {target.domain}")
            # هنا يتم ربطها بمنطق الفحص الأساسي (Pipeline) الخاص بك لتحديث النتائج
    except Exception as e:
        print(f"[ERROR] Scheduled job failed: {e}")
    finally:
        db.close()

# تهيئة وتشغيل الـ Scheduler في الخلفية
scheduler = BackgroundScheduler()
# جدولة الفحص ليعمل تلقائياً (مثلاً كل 8 ساعات لتغطية 3 مرات يومياً)
scheduler.add_job(scheduled_recon_job, 'interval', hours=8, id='recon_monitor_job', replace_existing=True)

def start_scheduler():
    if not scheduler.running:
        scheduler.start()
        print("[+] Background Recon Scheduler started successfully!")