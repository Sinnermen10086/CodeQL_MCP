import os
import subprocess
import json
import uuid
import shutil
from .query_scanner import collect_all_queries, get_query_metadata

# CodeQL路径配置
CODEQL_PATH = "E:\\codeql"
CODEQL_BIN = os.path.join(CODEQL_PATH, "codeql.exe")
CODEQL_QUERIES = r"E:\\codeql\\codeql-main"

def get_available_languages():
    """获取可用的编程语言列表"""
    return ["cpp", "csharp", "go", "java", "javascript", "python", "ruby"]

def get_available_queries(language):
    """获取指定语言的可用查询"""
    # 使用新的query_scanner模块获取查询
    all_queries = collect_all_queries(CODEQL_QUERIES)
    if language in all_queries:
        return all_queries[language]
    
    # 兜底使用老方法
    query_dir = os.path.join(CODEQL_QUERIES, language, "ql", "src")
    if not os.path.exists(query_dir):
        return []
    
    queries = []
    for root, dirs, files in os.walk(query_dir):
        for file in files:
            if file.endswith(".ql"):
                rel_path = os.path.relpath(os.path.join(root, file), CODEQL_QUERIES)
                queries.append(rel_path)
    return {"ql": queries, "qls": []}

def detect_language(src_path):
    """简单检测项目的主要编程语言"""
    extensions = {
        ".py": "python",
        ".java": "java",
        ".js": "javascript",
        ".ts": "javascript",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "cpp",
        ".go": "go",
        ".rb": "ruby"
    }
    
    ext_counts = {}
    for root, dirs, files in os.walk(src_path):
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in extensions:
                lang = extensions[ext]
                ext_counts[lang] = ext_counts.get(lang, 0) + 1
    
    if not ext_counts:
        return None
    
    return max(ext_counts.items(), key=lambda x: x[1])[0]

def call_codeql(src_path, query_path=None, output_path=None, language=None):
    """封装 CodeQL 调用并返回简洁结果"""
    # 检查CodeQL是否可用
    if not os.path.exists(CODEQL_BIN):
        return [f"错误：找不到CodeQL可执行文件，请确保CodeQL已正确安装在 {CODEQL_PATH}"]
    
    # 创建临时目录
    tmp_id = uuid.uuid4().hex
    tmp_db = f"./tmp_db_{tmp_id}"
    
    if not output_path:
        output_path = f"./codeql_results_{tmp_id}.sarif"
    
    try:
        os.makedirs(tmp_db, exist_ok=True)
        
        # 自动检测语言
        if not language:
            language = detect_language(src_path)
            if not language:
                return ["无法检测项目语言，请手动指定"]
        
        # 创建数据库
        print(f"[CodeQL] 正在为 {language} 项目创建数据库...")
        create_cmd = [
            CODEQL_BIN, "database", "create", tmp_db,
            f"--language={language}", f"--source-root={src_path}", "--overwrite"
        ]
        
        process = subprocess.run(create_cmd, capture_output=True, text=True)
        if process.returncode != 0:
            return [f"数据库创建失败: {process.stderr}"]
        
        # 如果没有指定查询路径，优先查找官方推荐的安全套件
        if not query_path:
            # 使用分类查询获取Security类别的第一个查询
            all_queries = collect_all_queries(CODEQL_QUERIES)
            if language in all_queries and "ql_by_category" in all_queries[language]:
                security_queries = all_queries[language]["ql_by_category"].get("Security", [])
                if security_queries:
                    query_path = os.path.join(CODEQL_QUERIES, security_queries[0])
                    print(f"[CodeQL] 自动选择安全查询: {os.path.basename(query_path)}")
            
            if not query_path:
                # 兜底：使用安全与质量套件
                suite_path = os.path.join(CODEQL_QUERIES, language, "ql", "src", "codeql-suites", f"{language}-security-and-quality.qls")
                if os.path.exists(suite_path):
                    query_path = suite_path
                else:
                    # 再兜底：查找 Security 目录
                    query_path = os.path.join(CODEQL_QUERIES, language, "ql", "src", "Security")
                    if not os.path.exists(query_path):
                        return [f"找不到 {language} 语言的安全查询"]
        
        # 获取查询文件的元数据
        if query_path and not query_path.endswith(".qls") and os.path.isfile(query_path):
            rel_path = os.path.relpath(query_path, CODEQL_QUERIES)
            metadata = get_query_metadata(CODEQL_QUERIES, rel_path)
            if metadata.get("description"):
                print(f"[CodeQL] 查询描述: {metadata.get('description')}")
            if metadata.get("severity") and metadata.get("severity") != "未知":
                print(f"[CodeQL] 严重程度: {metadata.get('severity')}")
            if metadata.get("tags"):
                print(f"[CodeQL] 标签: {', '.join(metadata.get('tags'))}")
        
        # 执行查询
        print(f"[CodeQL] 正在分析项目，使用查询: {os.path.basename(query_path)}")
        analyze_cmd = [
            CODEQL_BIN, "database", "analyze", tmp_db,
            os.path.abspath(query_path).replace("\\", "/"),
            "--format=sarif-latest", "--output", output_path, "--rerun",
            "--search-path", CODEQL_QUERIES
        ]
        
        process = subprocess.run(analyze_cmd, capture_output=True, text=True)
        if process.returncode != 0:
            return [f"分析失败: {process.stderr}"]

        # 解析 SARIF
        with open(output_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)

        results = []
        for run in sarif.get("runs", []):
            for r in run.get("results", []):
                if "locations" in r and r["locations"]:
                    loc = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    msg = r["message"]["text"]
                    region = r["locations"][0]["physicalLocation"].get("region", {})
                    line = region.get("startLine", "?")
                    rule_id = r.get("ruleId", "未知规则")
                    severity = r.get("properties", {}).get("severity", "警告")
                    
                    results.append({
                        "path": loc,
                        "line": line,
                        "message": msg,
                        "rule_id": rule_id,
                        "severity": severity
                    })
        
        if not results:
            return ["未发现安全问题"]
            
        return results
    
    finally:
        # 清理临时文件
        if os.path.exists(tmp_db):
            shutil.rmtree(tmp_db, ignore_errors=True)
