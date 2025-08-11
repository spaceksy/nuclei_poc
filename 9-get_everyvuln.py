import os
import shutil
import time
import hashlib
import subprocess
from datetime import datetime

POC_DIR = "poc"
TMP_DIR = "tmp"
VULN_BASE_DIR = "Vuln_Date"
TIMEOUT = 19800
START_TIME = time.time()

CATEGORY_RULES = {
    "FileUpload": ["fileupload", "upload"],
    "RCE": ["rce", "command-injection"],
    "SQLI": ["sql", "sqli"]
}

def ensure_dir(directory):
    os.makedirs(directory, exist_ok=True)

def get_file_hash(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def safe_remove(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"删除无效文件: {file_path}")

def move_file(src, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest):
        base, ext = os.path.splitext(dest)
        counter = 1
        while os.path.exists(f"{base}_{counter}{ext}"):
            counter += 1
        dest = f"{base}_{counter}{ext}"
    shutil.move(src, dest)
    print(f"移动文件: {src} -> {dest}")

def check_yaml_format(file_path):
    result = subprocess.run(
        ["./nuclei", "-t", file_path, "-silent"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    return "FTL" not in result.stdout and "FTL" not in result.stderr

def classify_and_copy(file_path, base_dir):
    """根据关键字分类并复制到对应目录"""
    file_name = os.path.basename(file_path).lower()
    content = open(file_path, encoding="utf-8", errors="ignore").read().lower()

    for category, keywords in CATEGORY_RULES.items():
        if any(kw in file_name or kw in content for kw in keywords):
            dest_dir = os.path.join(base_dir, category)
            ensure_dir(dest_dir)
            shutil.copy(file_path, dest_dir)
            print(f"已分类: {file_path} -> {dest_dir}")
            return
    print(f"未分类: {file_path}")

def main():
    ensure_dir(POC_DIR)
    if not os.path.exists(TMP_DIR):
        print("tmp/ 目录不存在，退出。")
        return

    today_dir = os.path.join(VULN_BASE_DIR, datetime.now().strftime("%Y-%m-%d"))
    ensure_dir(today_dir)

    processed_hashes = {get_file_hash(os.path.join(root, f))
                        for root, _, files in os.walk(POC_DIR)
                        for f in files if f.endswith(('.yml', '.yaml'))}

    yaml_files = [os.path.join(root, file)
                  for root, _, files in os.walk(TMP_DIR)
                  for file in files if file.endswith(('.yml', '.yaml'))]

    for file_path in yaml_files:
        if time.time() - START_TIME >= TIMEOUT:
            print("运行超时，退出。")
            return

        file_hash = get_file_hash(file_path)
        if file_hash in processed_hashes:
            safe_remove(file_path)
            continue

        if not check_yaml_format(file_path):
            safe_remove(file_path)
        else:
            processed_hashes.add(file_hash)
            new_poc_path = os.path.join(POC_DIR, os.path.relpath(file_path, TMP_DIR))
            move_file(file_path, new_poc_path)
            classify_and_copy(new_poc_path, today_dir)

    if not any(os.scandir(TMP_DIR)):
        shutil.rmtree(TMP_DIR, ignore_errors=True)
        print("tmp/ 目录已清空。")

if __name__ == "__main__":
    main()
