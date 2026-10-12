# ⚡ Recon & Monitoring Platform

An enterprise-grade automated reconnaissance and security monitoring platform built with **FastAPI**, **APScheduler**, **Tailwind CSS**, and **Telegram Bot Integration**. Designed for security engineers and bug hunters to achieve complete target isolation, real-time status tracking, and automated diff alerts.

---

## 🚀 Key Features

* **Complete Target Isolation:** Dedicated `raw` and `processed` storage directories created for every target domain.
* **Multi-Tool Recon Pipeline:** Automated execution pipeline encompassing subdomain enumeration, live host resolution and fingerprinting (`httpx`), endpoint crawling (`katana`), and vulnerability scanning (`nuclei`).
* **Diff Engine & Telegram Alerts:** Compares new scan results against historical database records and instantly pushes updates (new subdomains, endpoints, and JS files) to your Telegram chat.
* **Automated Background Scheduler:** Powered by `APScheduler` to run periodic re-scans and monitoring checks at customizable intervals.
* **Interactive Real-Time Dashboard:** Real-time polling interface built with Tailwind CSS featuring status bars, asset counters, live stage tracking, and one-click monitoring toggles.

---

## 🛠️ Tech Stack

* **Backend:** Python, FastAPI, SQLAlchemy, SQLite, APScheduler
* **Frontend:** Tailwind CSS, Jinja2 Templates, JavaScript (Polling Architecture)
* **Security & Recon Tools:** Subfinder, Amass, Httpx, Katana, Nuclei

---

## 📂 Project Structure

```text
recon-platform/
│
├── api/                  # API routes and web endpoints
├── core/                 # Database models, connection, and scheduler logic
├── modules/              # Recon tool wrappers (subdomains, resolver, crawler, vulnerability)
├── storage/              # Isolated target storage directories (raw/processed)
├── templates/            # Frontend HTML dashboard (Jinja2 + Tailwind)
├── workers/              # Execution engine and pipeline manager
├── main.py               # FastAPI application entry point
├── requirements.txt      # Python dependencies
└── README.md             # Project documentation
