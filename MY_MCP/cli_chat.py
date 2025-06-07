import json
import subprocess
import os
import re
import time
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from MCP_Tools.CodeQL.codeql_wrapper import call_codeql, detect_language
from MCP_Tools.project_analyzer import analyze_project
import glob
from fastapi import FastAPI, UploadFile, File, Form
from pydantic import BaseModel
import shutil

# —— 配置区 —— #
MODEL_PATH = "E:\\DeepSeek 1.5B"        # 模型路径
DEVICE      = "cuda" if torch.cuda.is_available() else "cpu"
OUTPUT_DIR = "results"  # 输出目录
CODEQL_PATH = "E:\\codeql"
CODEQL_QUERIES = r"E:\\codeql\\codeql-main"

# —— 加载模型 —— #
print("加载模型中...", end="", flush=True)
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    device_map="auto",
    torch_dtype=torch.float16,
    trust_remote_code=True
)
model.eval()
print(" 完成。")

def normalize_path(path):
    """标准化路径，处理引号和反斜杠"""
    # 移除引号
    path = path.strip('"\'')
    # 确保路径分隔符正确
    return os.path.normpath(path)

def is_valid_path(path):
    """检查路径是否有效"""
    try:
        path = normalize_path(path)
        # 检查路径是否存在
        if os.path.exists(path):
            return True
        # 检查是否是有效的Windows路径格式
        if re.match(r'^[a-zA-Z]:\\', path):
            return True
        # 检查是否是有效的Unix路径格式
        if path.startswith('/'):
            return True
        return False
    except:
        return False

def choose_query_file(user_input, available_queries, language):
    lang_queries = available_queries.get(language, {})
    # 优先 security-and-quality
    for q in lang_queries.get("qls", []):
        if "security-and-quality" in q:
            return q, "优先选择官方安全与质量套件"
    # 其次 security
    for q in lang_queries.get("qls", []):
        if "security" in q:
            return q, "优先选择安全相关套件"
    # 专项需求
    if "cve" in user_input.lower():
        for q in lang_queries.get("ql", []):
            if "cve" in q.lower():
                return q, "根据用户需求，选择CVE专项规则"
    if "sql注入" in user_input.lower() or "sql injection" in user_input.lower():
        for q in lang_queries.get("ql", []):
            if "sqlinjection" in q.lower() or "sql_injection" in q.lower():
                return q, "根据用户需求，选择SQL注入专项规则"
    # 兜底
    if lang_queries.get("qls"):
        return lang_queries["qls"][0], "默认选择第一个套件"
    if lang_queries.get("ql"):
        return lang_queries["ql"][0], "默认选择第一个规则"
    return None, "未找到合适的查询文件"

def auto_analyze_project(path):
    """自动分析项目并返回自然语言安全报告"""
    # 标准化路径
    path = normalize_path(path)
    if not os.path.exists(path):
        return f"错误：路径 '{path}' 不存在或无法访问"
    print(f"正在分析项目: {path}...")
    
    # OSV-Scanner 扫描依赖
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    # 调用osv-scanner扫描整个项目
    osv_report_path = os.path.join(OUTPUT_DIR, f"osv_report_{timestamp}.json")
    print(f"正在使用 OSV-Scanner 扫描项目依赖...")
    try:
        # 使用与截图中相同的命令格式
        cmd = f'osv-scanner.exe scan source "{path}" --json --output "{osv_report_path}"'
        print(f"执行命令: {cmd}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"OSV-Scanner 扫描完成，结果已保存到 {osv_report_path}")
        else:
            print(f"OSV-Scanner 扫描失败：{result.stderr}")
            # 尝试不带输出重定向的简单命令
            simple_cmd = f'osv-scanner.exe scan source "{path}"'
            print(f"尝试简单命令: {simple_cmd}")
            simple_result = subprocess.run(simple_cmd, shell=True)
            if simple_result.returncode == 0:
                print("简单命令扫描成功，但结果未保存到文件")
    except Exception as e:
        print(f"OSV-Scanner 执行异常: {e}")
    
    # 1. 项目结构分析
    project_info = analyze_project(path)
    if "error" in project_info:
        return f"分析错误: {project_info['error']}"
    # 2. 检测语言并执行CodeQL分析
    language = detect_language(path)
    if not language:
        return f"项目分析完成，但无法检测主要编程语言\n\n项目名称: {project_info['project_name']}\n文件总数: {project_info['total_files']}\n代码行数: {project_info['total_lines']}"
    # 自动选择 QLS 套件或 QL 单条规则
    query_path, reason = choose_query_file(path, project_info.get("available_queries", {}), language)
    if query_path and not os.path.isabs(query_path):
        query_path = os.path.abspath(os.path.join(CODEQL_QUERIES, query_path))
    if query_path:
        query_path = query_path.replace("\\", "/")
    output_path = os.path.join(OUTPUT_DIR, f"codeql_results_{os.path.basename(path)}.sarif")
    codeql_results = call_codeql(path, query_path=query_path, output_path=output_path, language=language)
    # 检查 SARIF 文件是否存在
    if not os.path.exists(output_path):
        return f"CodeQL 分析失败，未生成结果文件。请检查数据库创建和分析阶段是否有报错。\n详细信息：{codeql_results}"
    findings = summarize_sarif(output_path)
    # 只传递结构化信息和风格指令给大模型，由大模型自由生成报告
    return generate_natural_report(findings, project_info, path)

def summarize_sarif(sarif_path):
    with open(sarif_path, "r", encoding="utf-8") as f:
        sarif = json.load(f)
    findings = []
    for run in sarif.get("runs", []):
        for r in run.get("results", []):
            if "locations" in r and r["locations"]:
                loc = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                line = r["locations"][0]["physicalLocation"].get("region", {}).get("startLine", "?")
                msg = r["message"]["text"]
                rule_id = r.get("ruleId", "未知规则")
                severity = r.get("properties", {}).get("severity", "警告")
                findings.append({
                    "file": loc,
                    "line": line,
                    "rule": rule_id,
                    "severity": severity,
                    "desc": msg
                })
    return findings

def summarize_osv_reports(output_dir, timestamp=None):
    """读取并汇总OSV-Scanner生成的依赖漏洞报告"""
    osv_findings = []
    
    # 查找最新的OSV报告(如果未指定时间戳)
    if timestamp:
        report_pattern = f"osv_report_*_{timestamp}.json"
    else:
        report_pattern = "osv_report_*.json"
        
    osv_reports = glob.glob(os.path.join(output_dir, report_pattern))
    
    # 按修改时间排序，获取最新报告
    if not timestamp:
        osv_reports.sort(key=os.path.getmtime, reverse=True)
    
    # 读取每个报告文件
    for report_file in osv_reports:
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
                
                # 解析OSV-Scanner报告格式
                if "results" in report_data:
                    for package_result in report_data["results"]:
                        pkg_name = package_result.get("package", {}).get("name", "未知包")
                        pkg_version = package_result.get("package", {}).get("version", "未知版本")
                        
                        for vuln in package_result.get("vulnerabilities", []):
                            osv_findings.append({
                                "package": pkg_name,
                                "version": pkg_version,
                                "id": vuln.get("id", "未知ID"),
                                "summary": vuln.get("summary", "无描述"),
                                "severity": vuln.get("database_specific", {}).get("severity", "未知"),
                                "details": vuln.get("details", "无详细信息")
                            })
        except Exception as e:
            print(f"读取OSV报告 {report_file} 出错: {e}")
            
    return osv_findings

def generate_natural_report(findings, project_info, user_input):
    osv = summarize_osv_reports(OUTPUT_DIR)
    osv_summary = "本次依赖扫描未发现任何依赖包的漏洞。" if not osv else json.dumps(osv[:10], ensure_ascii=False, indent=2)
    prompt = f"""你是一名资深代码安全专家。请根据以下项目分析结果，生成一份专业、自然、面向开发者的安全分析报告。

项目名称：{project_info['project_name']}
项目路径：{project_info.get('project_path', '')}
文件总数：{project_info.get('total_files', '')}
代码行数：{project_info.get('total_lines', '')}
主要语言：{project_info['file_types']}
用户需求：{user_input}

===== 代码安全分析结果 =====
本次代码分析共发现 {len(findings)} 个安全相关问题，关键信息如下（仅供参考）：
{json.dumps(findings[:10], ensure_ascii=False, indent=2)}

===== 依赖安全分析结果 =====
{osv_summary}

请用真实安全专家的口吻，像写正式安全评估报告一样，综合分析本次结果，将代码漏洞和依赖漏洞结合起来，指出主要风险、典型漏洞、整改建议等。风格可以灵活，不要机械分点，适当穿插解释和建议。不要直接输出原始数据。
报告应当包含以下部分：
1. 总体安全评分(1-10分)
2. 代码安全性分析
3. 依赖安全性分析
4. 综合风险评估
5. 修复建议
6. 风险控制策略
7. 监控计划

请直接输出正式报告内容，不要重复题目和原始数据。"""
    inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
    out = model.generate(**inputs, max_new_tokens=768)
    text = tokenizer.decode(out[0], skip_special_tokens=True)
    # 只保留"助手："后面的内容，避免输出 prompt
    if "助手：" in text:
        text = text.split("助手：", 1)[-1].strip()
    # 只保留前60行，防止无限输出
    text = "\n".join(text.splitlines()[:60])
    return text

def call_llm(prompt):
    inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
    out = model.generate(**inputs, max_new_tokens=256)
    text = tokenizer.decode(out[0], skip_special_tokens=True)
    return text

# 在chat_loop外部定义
history = []

def check_identity_question(user_input):
    """
    判断用户输入是否为身份/模型相关问题
    """
    keywords = [
        "你是谁", "你是什么模型", "你的身份", "你是哪个模型", "你是", "who are you", "what model", "你的名字", "你叫什么"
    ]
    return any(k in user_input.lower() for k in keywords)

def build_history_prompt(history, user_input):
    """
    构造带历史的prompt
    """
    prompt = "你是一名资深的智能编程助手，基于claude-4-opus-thinking模型，深度集成于Cursor IDE。\n"
    prompt += "以下是你与用户的多轮对话历史，请结合上下文，理解用户需求并给出专业、自然、流畅的中文回复。\n\n"
    for i, turn in enumerate(history[-5:]):  # 只取最近5轮，防止prompt过长
        prompt += f"用户：{turn['user']}\n助手：{turn['assistant']}\n"
    prompt += f"用户：{user_input}\n助手："
    return prompt

def extract_path(user_input):
    match = re.search(r"[a-zA-Z]:\\[^\s\"']+", user_input)
    if match:
        return match.group(0)
    return None

def chat_loop():
    history = []
    print("\n=== MCP 安全分析系统 (输入 quit 或 exit 结束) ===")
    while True:
        user_input = input("\n你：").strip()
        if user_input.lower() in ("quit", "exit"):
            break

        if check_identity_question(user_input):
            assistant_reply = "您好，我是依托claude-4-opus-thinking模型的智能助手，在Cursor IDE中为您提供代码编写和问题解答服务，你可以直接告诉我你的需求。"
            print(f"\n系统：{assistant_reply}")
            history.append({"user": user_input, "assistant": assistant_reply})
            continue

        # 路径提取与判断
        path = extract_path(user_input)
        if path and os.path.exists(path):
            result = auto_analyze_project(path)
            print(f"\n系统：{result}")
            history.append({"user": user_input, "assistant": result})
            continue

        # 普通对话
        prompt = build_history_prompt(history, user_input)
        prompt += "\n请只用中文回答，不要输出英文。"
        inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
        out = model.generate(**inputs, max_new_tokens=256)
        text = tokenizer.decode(out[0], skip_special_tokens=True)
        assistant_reply = text.split("助手：")[-1].strip()
        print(f"\n系统：{assistant_reply}")
        history.append({"user": user_input, "assistant": assistant_reply})

    print("\n分析会话结束。")

if __name__ == "__main__":
    chat_loop()

app = FastAPI(title="MCP 安全分析API", description="本地大模型+CodeQL+OSV一体化安全分析接口")

class AnalyzeRequest(BaseModel):
    project_path: str

@app.post("/analyze_sync")
def analyze_sync(req: AnalyzeRequest):
    """
    同步分析本地项目路径，直接返回安全报告
    """
    result = auto_analyze_project(req.project_path)
    return {"report": result}

@app.post("/analyze_upload")
def analyze_upload(file: UploadFile = File(...)):
    """
    上传zip压缩包，自动解压到临时目录并分析
    """
    tmp_dir = f"tmp_upload_{file.filename}"
    os.makedirs(tmp_dir, exist_ok=True)
    zip_path = os.path.join(tmp_dir, file.filename)
    with open(zip_path, "wb") as f:
        shutil.copyfileobj(file.file, f)
    # 解压
    import zipfile
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(tmp_dir)
    # 假设解压后只有一个主目录
    subdirs = [os.path.join(tmp_dir, d) for d in os.listdir(tmp_dir) if os.path.isdir(os.path.join(tmp_dir, d))]
    project_dir = subdirs[0] if subdirs else tmp_dir
    result = auto_analyze_project(project_dir)
    shutil.rmtree(tmp_dir, ignore_errors=True)
    return {"report": result}
