import os
import json
import time
import shutil
import tempfile
import zipfile
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import JSONResponse

# 导入MCP功能
from MCP_Tools.project_analyzer import analyze_project
from MCP_Tools.CodeQL.codeql_wrapper import call_codeql, detect_language
import subprocess
import glob

# 创建API应用
app = FastAPI(
    title="MCP API",
    description="代码安全分析系统API",
    version="1.0.0"
)

# 添加CORS中间件，允许前端跨域访问
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应限制为特定域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 配置
OUTPUT_DIR = "results"  # 输出目录
TEMP_DIR = "temp"       # 临时目录，用于解压上传的文件

# 确保输出和临时目录存在
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# 数据模型
class AnalyzeRequest(BaseModel):
    project_path: str
    
class AnalyzeResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None

# 模型加载标志
model_loaded = False
model = None
tokenizer = None

def load_model():
    """按需加载模型"""
    global model, tokenizer, model_loaded
    
    if model_loaded:
        return model, tokenizer
        
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    
    MODEL_PATH = "E:\\DeepSeek 1.5B"  # 模型路径
    print("正在加载模型...", end="", flush=True)
    
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        device_map="auto",
        torch_dtype=torch.float16,
        trust_remote_code=True
    )
    model.eval()
    print(" 完成。")
    
    model_loaded = True
    return model, tokenizer

def call_llm(prompt, max_tokens=2048):
    """调用大语言模型"""
    model, tokenizer = load_model()
    
    import torch
    device = "cuda" if torch.cuda.is_available() else "cpu"
    
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    out = model.generate(**inputs, max_new_tokens=max_tokens)
    response = tokenizer.decode(out[0], skip_special_tokens=True)
    
    # 提取实际回复内容
    lines = response.split('\n')
    for i, line in enumerate(lines):
        if "项目安全总体评分" in line:
            return '\n'.join(lines[i:])
    
    return response

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

def summarize_sarif(sarif_path):
    """解析SARIF格式的CodeQL结果"""
    findings = []
    try:
        with open(sarif_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)
            
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
    except Exception as e:
        print(f"解析SARIF文件出错: {e}")
    
    return findings

def analyze_project_internal(project_path):
    """项目分析内部实现"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    result = {
        "timestamp": timestamp,
        "project_path": project_path,
        "project_info": None,
        "osv_findings": [],
        "codeql_findings": [],
        "ai_report": None
    }
    
    # 1. 调用osv-scanner扫描依赖
    osv_report_path = os.path.join(OUTPUT_DIR, f"osv_report_{timestamp}.json")
    print(f"正在使用 OSV-Scanner 扫描项目依赖...")
    try:
        cmd = f'osv-scanner.exe scan source "{project_path}" --json --output "{osv_report_path}"'
        subprocess.run(cmd, shell=True, capture_output=True, text=True)
        result["osv_findings"] = summarize_osv_reports(OUTPUT_DIR, timestamp)
    except Exception as e:
        print(f"OSV-Scanner 执行异常: {e}")
    
    # 2. 分析项目结构
    print(f"正在分析项目结构...")
    project_info = analyze_project(project_path)
    result["project_info"] = project_info
    
    if "error" in project_info:
        result["error"] = project_info["error"]
        return result
    
    # 3. 使用CodeQL进行安全分析
    print(f"正在使用CodeQL进行安全分析...")
    detected_lang = detect_language(project_path)
    
    if detected_lang:
        codeql_output = os.path.join(OUTPUT_DIR, f"codeql_results_{timestamp}.sarif")
        codeql_results = call_codeql(project_path, output_path=codeql_output, language=detected_lang)
        
        # 检查SARIF文件是否存在
        if os.path.exists(codeql_output):
            result["codeql_findings"] = summarize_sarif(codeql_output)
    
    # 4. 使用大模型进行综合分析
    print(f"正在使用大模型进行综合分析...")
    
    # 准备提示词
    prompt = f"""你是一个代码安全分析专家，请根据以下项目信息、代码分析结果和依赖漏洞扫描结果，对该项目进行全面的安全评估:

项目名称: {project_info.get('project_name', '未知')}
项目路径: {project_info.get('project_path', '未知')}
文件总数: {project_info.get('total_files', 0)}
代码行数: {project_info.get('total_lines', 0)}
主要语言: {detected_lang or '未检测到'}

===== 代码安全分析结果 =====
代码分析发现了 {len(result["codeql_findings"])} 个潜在问题。
{json.dumps(result["codeql_findings"][:10], ensure_ascii=False, indent=2)}

===== 依赖安全分析结果 =====
依赖扫描发现了 {len(result["osv_findings"])} 个漏洞。
{json.dumps(result["osv_findings"][:10], ensure_ascii=False, indent=2)}

请提供以下内容:
1. 项目安全总体评分(1-10分)
2. 代码安全性分析
3. 依赖安全性分析
4. 综合风险评估
5. 修复和加固建议

请以中文回答，回答要简洁专业。
"""
    
    ai_analysis = call_llm(prompt)
    result["ai_report"] = ai_analysis
    
    # 保存大模型分析结果
    ai_analysis_path = os.path.join(OUTPUT_DIR, f"ai_analysis_{timestamp}.txt")
    with open(ai_analysis_path, 'w', encoding='utf-8') as f:
        f.write(ai_analysis)
    
    return result

@app.get("/")
def read_root():
    """API根路径"""
    return {"message": "MCP代码安全分析系统API"}

@app.post("/analyze")
def analyze_project(request: AnalyzeRequest):
    """分析本地项目路径"""
    project_path = request.project_path
    
    # 路径校验
    if not os.path.exists(project_path):
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"路径不存在: {project_path}"}
        )
    
    try:
        # 调用内部分析函数
        result = analyze_project_internal(project_path)
        return {"success": True, "message": "分析完成", "data": result}
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"分析失败: {str(e)}\n{error_details}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"分析失败: {str(e)}"}
        )

# 添加一个替代端点，直接接受字符串路径
@app.post("/analyze_path")
def analyze_path(request: dict):
    """分析本地项目路径（接受简单的字符串路径）"""
    project_path = request.get("path")
    
    if not project_path:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "请提供项目路径(path)"}
        )
    
    # 路径校验
    if not os.path.exists(project_path):
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": f"路径不存在: {project_path}"}
        )
    
    try:
        # 调用内部分析函数
        result = analyze_project_internal(project_path)
        return {"success": True, "message": "分析完成", "data": result}
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"分析失败: {str(e)}\n{error_details}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"分析失败: {str(e)}"}
        )

@app.post("/analyze_upload")
def analyze_upload(file: UploadFile = File(...)):
    """分析上传的项目ZIP包"""
    # 检查文件扩展名
    if not file.filename.lower().endswith('.zip'):
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "只支持ZIP格式的项目包"}
        )
    
    # 创建临时目录
    temp_dir = os.path.join(TEMP_DIR, f"upload_{time.strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(temp_dir, exist_ok=True)
    
    try:
        # 保存上传的文件
        file_path = os.path.join(temp_dir, file.filename)
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        
        # 解压ZIP文件
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # 分析解压后的项目
        result = analyze_project_internal(extract_dir)
        
        return {"success": True, "message": "分析完成", "data": result}
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": f"分析失败: {str(e)}"}
        )
    finally:
        # 清理临时文件（可选，取决于您是否需要保留上传的文件）
        # shutil.rmtree(temp_dir, ignore_errors=True)
        pass

# 启动脚本
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("mcp_api:app", host="127.0.0.1", port=8000, reload=True) 