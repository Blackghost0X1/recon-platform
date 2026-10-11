import sys
import argparse
import uvicorn
from core.database import init_db
from workers.engine import run_target_pipeline

def main():
    # تهيئة قاعدة البيانات تلقائياً عند أي تشغيل
    init_db()

    parser = argparse.ArgumentParser(description="Professional Automated Recon & Monitoring Platform for Bug Hunting")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # أمر تشغيل الـ API
    api_parser = subparsers.add_parser("api", help="Start the FastAPI backend server")
    api_parser.add_argument("--host", default="127.0.0.1", help="Host IP address (default: 127.0.0.1)")
    api_parser.add_argument("--port", type=int, default=8000, help="Port number (default: 8000)")

    # أمر تشغيل الاستطلاع يدوياً عبر الـ CLI لهدف معين
    recon_parser = subparsers.add_parser("recon", help="Run the full recon pipeline for a specific target")
    recon_parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")

    args = parser.parse_args()

    if args.command == "api":
        print(f"[*] Starting Recon Platform API Server on http://{args.host}:{args.port} ...")
        uvicorn.run("api.main:app", host=args.host, port=args.port, reload=True)

    elif args.command == "recon":
        domain = args.domain.strip().lower()
        print(f"[*] Triggering CLI Recon Pipeline for target: {domain}")
        run_target_pipeline(domain)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()