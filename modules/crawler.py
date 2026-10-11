import subprocess
import os

def run_crawler(target_raw_dir: str) -> str:
    """
    يقرأ ملف الـ live_hosts.txt ويستخدم أداة katana لزحف المواقع وسحب
    جميع الـ Endpoints والـ URLs وملفات الجافاسكريبت (JS Files) بسرعة فائقة،
    ويحفظ النتائج داخل مجلد الهدف المعزول.
    """
    input_live_hosts = os.path.join(target_raw_dir, "live_hosts.txt")
    output_urls = os.path.join(target_raw_dir, "all_urls.txt")

    if not os.path.exists(input_live_hosts):
        print(f"[-] Live hosts file not found at {input_live_hosts}. Run resolver first.")
        return ""

    # أمر katana المحدث للسرعة الفائقة والزحف الذكي
    # -list: ملف السب دومينات أو الـ URLs الحية
    # -d 2: تقليل عمق الزحف للسرعة
    # -c 50: زيادة عدد خيوط التوازي (Concurrency)
    # -timeout 5: تقليل وقت الانتظار للروابط البطيئة
    # -jc: تفعيل استخراج ملفات الـ JS والروابط المخفية
    # -fx: تصفية الملفات والامتدادات غير المهمة (صور، وسائط، إلخ)
    # -silent: تقليل المخرجات في الـ Terminal
    cmd = [
        "katana",
        "-list", input_live_hosts,
        "-d", "3",
        "-c", "50",
        "-timeout", "5",
        "-jc",
        "-fx",
        "-o", output_urls,
        "-silent"
    ]

    try:
        print(f"[*] Starting high-speed web crawling and endpoint extraction with Katana...")
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        if os.path.exists(output_urls):
            # تصفية الروابط وحذف التكرار
            with open(output_urls, "r") as f:
                lines = f.readlines()
            
            unique_urls = sorted(set(line.strip() for line in lines if line.strip()))
            
            with open(output_urls, "w") as f:
                for url in unique_urls:
                    f.write(url + "\n")
                    
            print(f"[+] Crawling completed. Total unique URLs/Endpoints found: {len(unique_urls)}")
            print(f"[+] Saved securely to: {output_urls}")
            
            # استخراج ملفات الجافاسكريبت (JS Files) في ملف مستقل لسهولة تحليلها لاحقاً
            js_output_file = os.path.join(target_raw_dir, "js_files.txt")
            js_urls = [url for url in unique_urls if ".js" in url.lower()]
            
            with open(js_output_file, "w") as f_js:
                for js in js_urls:
                    f_js.write(js + "\n")
            print(f"[+] Extracted {len(js_urls)} JavaScript files to {js_output_file}")

        return output_urls

    except FileNotFoundError:
        print("[-] Error: 'katana' is not installed or missing from system PATH.")
        return ""
    except subprocess.CalledProcessError as e:
        print(f"[-] Katana error: {e.stderr}")
        return ""