import subprocess
import os

def run_tool(cmd_list, tool_name, output_file):
    """دالة مساعدة لتشغيل أي أداة بلطف وتجنب توقف التابع لو أداة غير مثبتة"""
    try:
        print(f"[*] Running {tool_name}...")
        result = subprocess.run(cmd_list, capture_output=True, text=True, check=True)
        if result.stdout:
            with open(output_file, "a") as f:
                f.write(result.stdout + "\n")
        print(f"[+] {tool_name} finished successfully.")
    except FileNotFoundError:
        print(f"[-] Warning: '{tool_name}' is not installed or missing from PATH.")
    except subprocess.CalledProcessError as e:
        print(f"[-] {tool_name} error: {e.stderr}")

def enumerate_subdomains(target_domain: str, target_raw_dir: str) -> str:
    """
    يشغل أقوى 4 أدوات في السوق (Subfinder, Amass, Assetfinder, Findomain)
    ويجمع النتائج ويزيل التكرار ويحفظها حصرياً داخل المجلد المعزول للهدف.
    """
    temp_sub_file = os.path.join(target_raw_dir, "temp_subs.txt")
    final_output_file = os.path.join(target_raw_dir, "subdomains.txt")
    
    # التأكد من نظافة الملف المؤقت إن وجد
    if os.path.exists(temp_sub_file):
        os.remove(temp_sub_file)

    print(f"[*] Starting multi-tool subdomain enumeration for: {target_domain}")

    # 1. Subfinder (سرعة عالية ومصادر ضخمة)
    run_tool(["subfinder", "-d", target_domain, "-silent"], "Subfinder", temp_sub_file)

    # 2. Assetfinder (ممتاز لجلب نتائج خفيفة وسريعة)
    run_tool(["assetfinder", "--subs-only", target_domain], "Assetfinder", temp_sub_file)

    # 3. Findomain (أداة سريعة جداً مبنية بلغة قوية ولها نتائج ممتازة)
    run_tool(["findomain", "-t", target_domain, "--quiet"], "Findomain", temp_sub_file)

    # 4. Amass (العملاق للبحث العميق وجمع الـ Passive OSINT)
    run_tool(["amass", "enum", "-passive", "-d", target_domain], "Amass", temp_sub_file)

    # تصفية النتائج وحذف المكرر وترتيبها لضمان نظافة البيانات
    if os.path.exists(temp_sub_file):
        with open(temp_sub_file, "r") as f:
            lines = f.readlines()
        
        # تنظيف وفلترة السطور (إزالة الفراغات، الـ Wildcards الزائدة، وتحويلها لـ Set فريدة)
        unique_subs = set()
        for line in lines:
            cleaned = line.strip().lower()
            if cleaned and not cleaned.startswith("*."):
                unique_subs.add(cleaned)
        
        sorted_subs = sorted(unique_subs)
        
        # كتابة النتيجة النهائية في الملف المعزول الخاص بالهدف حصرياً
        with open(final_output_file, "w") as f:
            for sub in sorted_subs:
                f.write(sub + "\n")
                
        # حذف الملف المؤقت
        os.remove(temp_sub_file)
        print(f"[+] Subdomain enumeration completed for {target_domain}.")
        print(f"[+] Total unique subdomains found: {len(sorted_subs)}")
        print(f"[+] Saved securely to: {final_output_file}")
    else:
        print("[-] No subdomains were collected or tools failed to execute.")
        
    return final_output_file