import os
import shutil
import subprocess
import time
import hashlib
from datetime import datetime

POC_DIR, TMP_DIR, TIMEOUT, START_TIME = "poc", "tmp", 19800, time.time()

# 预定义分类关键字及对应目录名（根据需求自由修改）
CATEGORY_KEYWORDS = {
    "FileUpload": "FileUpload",
    "RCE": "RCE",
    "SQLI": "SQLI",
    # 可以继续添加更多分类
}

def ensure_dir(directory):
    os.makedirs(directory, exist_ok=True)

def safe_remove(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"poc校验失败，已删除文件: {file_path}")

def classify_file(file_path):
    """根据文件内容或文件名关键词判断分类"""
    # 这里用最简单的方式：判断文件名是否包含关键字，不包含的话归为 Other
    filename = os.path.basename(file_path).lower()
    for keyword, category in CATEGORY_KEYWORDS.items():
        if keyword.lower() in filename:
            return category
    # 如果你想根据文件内容判断，也可以打开文件扫描关键词
    # with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
    #     content = f.read()
    #     for keyword, category in CATEGORY_KEYWORDS.items():
    #         if keyword.lower() in content.lower():
    #             return category
    return "Other"

def move_file(src, base_poc_dir):
    # 生成当天日期目录名，比如 Vuln_Date/2025-8-11/
    today_str = datetime.now().strftime("%Y-%m-%d")
    date_dir = os.path.join(base_poc_dir, "Vuln_Date", today_str)
    
    category = classify_file(src)
    dest_dir = os.path.join(date_dir, category)
    
    ensure_dir(dest_dir)
    
    dest = os.path.join(dest_dir, os.path.basename(src))
    
    try:
        # 避免同名覆盖，增加编号
        if os.path.exists(dest):
            base, ext = os.path.splitext(dest)
            counter = 1
            new_dest = f"{base}_{counter}{ext}"
            while os.path.exists(new_dest):
                counter += 1
                new_dest = f"{base}_{counter}{ext}"
            dest = new_dest
        
        shutil.move(src, dest)
        print(f"poc校验成功，已移动文件: {src} -> {dest}")
    except Exception as e:
        print(f"移动文件出错: {src} -> {dest}, 错误: {e}")

def check_yaml_format(file_path):
    result = subprocess.run(["./nuclei", "-t", file_path, "-silent"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return "FTL" not in result.stdout and "FTL" not in result.stderr

def get_file_hash(file_path):
    """计算文件的hash值"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

ensure_dir(POC_DIR)
if not os.path.exists(TMP_DIR):
    print("tmp/ 目录不存在，退出。")
    exit(0)

yaml_files = [os.path.join(root, file) for root, _, files in os.walk(TMP_DIR)
              for file in files if file.endswith(('.yml', '.yaml'))]
if not yaml_files:
    shutil.rmtree(TMP_DIR, ignore_errors=True)
    print("tmp/ 目录已删除。")
    exit(0)

processed_files_hash = {}

for file_path in yaml_files:
    if time.time() - START_TIME >= TIMEOUT:
        print("运行时间已超过 5 小时 30 分钟，强制退出。")
        exit(0)

    file_hash = get_file_hash(file_path)

    if file_hash in processed_files_hash:
        safe_remove(file_path)
        continue

    if not check_yaml_format(file_path):
        safe_remove(file_path)
    else:
        processed_files_hash[file_hash] = file_path
        move_file(file_path, POC_DIR)

if not any(os.scandir(TMP_DIR)):
    shutil.rmtree(TMP_DIR, ignore_errors=True)
    print("tmp/ 目录已删除。")

print("POC 检查完成。")
