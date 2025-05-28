import json
import subprocess
import os
import re
from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
from MCP_Tools.CodeQL.codeql_wrapper import call_codeql, detect_language
from MCP_Tools.project_analyzer import analyze_project

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
    torch_dtype=torch.float16
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

def generate_natural_report(findings, project_info, user_input):
    prompt = f"""你是一名资深代码安全专家。请根据以下项目分析结果，生成一份专业、自然、面向开发者的安全分析报告。
项目名称：{project_info['project_name']}
主要语言：{project_info['file_types']}
用户需求：{user_input}
本次自动化分析共发现 {len(findings)} 个安全相关问题，关键信息如下（仅供参考）：
{json.dumps(findings[:10], ensure_ascii=False, indent=2)}

请用真实安全专家的口吻，像写正式安全评估报告一样，综合分析本次结果，指出主要风险、典型漏洞、整改建议等。风格可以灵活，不要机械分点，适当穿插解释和建议。不要直接输出原始数据。
"""
    inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
    out = model.generate(**inputs, max_new_tokens=768)
    text = tokenizer.decode(out[0], skip_special_tokens=True)
    return text

def chat_loop():
    print("\n=== MCP 安全分析系统 (输入 quit 或 exit 结束) ===")
    print("提示: 你可以直接输入项目路径进行自动分析，或者询问安全相关问题")
    while True:
        user_input = input("\n你：").strip()
        if user_input.lower() in ("quit", "exit"): 
            break
            
        # 检查是否是路径
        if is_valid_path(user_input):
            # 直接分析项目
            result = auto_analyze_project(user_input)
            print(f"\n系统：{result}")
            continue
        
        # 构造 prompt
        prompt = f"""你是代码安全专家，能理解用户需求并给出专业回答。
用户请求：{user_input}

如果用户提到了路径或项目分析，请回复：
"我可以帮您分析项目，请提供完整的项目路径。例如Windows系统上的'C:\\项目路径'或Linux系统上的'/项目路径'"

如果用户询问了安全相关问题，请简洁专业地回答。
"""

        # 模型推理
        inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
        out = model.generate(**inputs, max_new_tokens=512)
        text = tokenizer.decode(out[0], skip_special_tokens=True)
        
        # 提取实际回复内容，去除提示词部分
        lines = text.split('\n')
        response_start = False
        response = []
        
        for line in lines:
            if "用户请求" in line:
                response_start = True
                continue
            if response_start and not (line.startswith("如果") or "回复：" in line or not line.strip()):
                response.append(line)
        
        # 如果没能正确提取，使用简单的回退方法
        if not response:
            parts = text.split("用户请求：")
            if len(parts) > 1:
                parts = parts[1].split("如果用户")
                response = [parts[0].strip()]
        
        # 输出处理后的回复
        final_response = "\n".join(response).strip()
        # 避免重复用户请求的情况
        if user_input in final_response:
            final_response = final_response.replace(user_input, "").strip()
        
        print(f"\n系统：{final_response}")

if __name__ == "__main__":
    chat_loop()
    print("\n分析会话结束。")
