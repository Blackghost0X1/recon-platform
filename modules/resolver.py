import subprocess
import os
import json

def resolve_and_fingerprint(target_raw_dir: str) -> str:
    """
    يقرأ ملف subdomains.txt الخاص بالهدف، ويستخدم أداة httpx للتحقق من الـ Live Hosts،
    وجلب الـ Status Codes والتقنيات (Technologies)، ويحفظ النتائج بتنسيق JSON مفصل
    في مجلد الهدف المعزول لضمان عدم التداخل.
    """
    input_subdomains = os.path.join(target_raw_dir, "subdomains.txt")
    output_live_json = os.path.join(target_raw_dir, "live_hosts.json")
    output_live_txt = os.path.join(target_raw_dir, "live_hosts.txt")

    if not os.path.exists(input_subdomains):
        print(f"[-] Subdomains file not found at {input_subdomains}. Run subdomain enumeration first.")
        return ""

    # تحديد المسار الكامل لأداة httpx الخاصة بـ Go تفادياً لأي تداخل
    home_dir = os.path.expanduser("~")
    httpx_path = os.path.join(home_dir, "go", "bin", "httpx")

# إذا لم تكن موجودة هناك، يمكنك تجربتها بالأمر العادي بعد إصلاح الـ PATH
    cmd = [
    httpx_path if os.path.exists(httpx_path) else "httpx",
    "-l", input_subdomains,
    "-sc",
    "-tech-detect",
    "-json",
    "-o", output_live_json,
    "-silent"
]

    try:
        print(f"[*] Starting live host resolution and technology fingerprinting...")
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[+] Live resolution completed. Results saved to {output_live_json}")

        # استخراج قائمة بسيطة بالـ URLs الحية في ملف نصي للاستخدامات اللاحقة (مثل الـ Crawler)
        if os.path.exists(output_live_json):
            live_urls = []
            with open(output_live_json, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        if "url" in data:
                            live_urls.append(data["url"])
                    except json.JSONDecodeError:
                        continue
            
            with open(output_live_txt, "w") as f_out:
                for url in live_urls:
                    f_out.write(url + "\n")
            
            print(f"[+] Extracted {len(live_urls)} live active URLs to {output_live_txt}")

        return output_live_json

    except FileNotFoundError:
        print("[-] Error: 'httpx' is not installed or missing from system PATH.")
        return ""
    except subprocess.CalledProcessError as e:
        print(f"[-] Httpx error: {e.stderr}")
        return ""