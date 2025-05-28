import os
import sys
import json
import time
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from MCP_Tools.project_analyzer import analyze_project
from MCP_Tools.CodeQL.codeql_wrapper import call_codeql, get_available_languages, get_available_queries, detect_language

# ------ 配置区 ------ #
MODEL_PATH = "E:\\DeepSeek 1.5B"  # 模型路径
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
OUTPUT_DIR = "results"  # 输出目录

def load_model():
    """加载大模型"""
    print("正在加载模型...", end="", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        device_map="auto",
        torch_dtype=torch.float16
    )
    model.eval()
    print(" 完成。")
    return model, tokenizer

def query_model(model, tokenizer, prompt, max_tokens=512):
    """向模型提交查询"""
    inputs = tokenizer(prompt, return_tensors="pt").to(DEVICE)
    out = model.generate(**inputs, max_new_tokens=max_tokens)
    response = tokenizer.decode(out[0], skip_special_tokens=True)
    
    # 提取实际回复内容
    lines = response.split('\n')
    result = []
    capture = False
    for line in lines:
        if "项目安全总体评分" in line or "分" in line and len(result) == 0:
            capture = True
        if capture:
            result.append(line)
    
    if not result:
        return response
    return '\n'.join(result)

def process_project(project_path, model, tokenizer):
    """处理项目：分析、CodeQL扫描和大模型分析"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print("="*50)
    print(f"开始分析项目: {project_path}")
    print("="*50)
    
    # 步骤1: 分析项目结构
    print(f"\n[1/3] 正在分析项目结构...")
    project_info = analyze_project(project_path)
    
    if "error" in project_info:
        print(f"错误: {project_info['error']}")
        return
    
    # 保存项目分析结果
    project_info_path = os.path.join(OUTPUT_DIR, f"project_info_{timestamp}.json")
    with open(project_info_path, 'w', encoding='utf-8') as f:
        json.dump(project_info, f, ensure_ascii=False, indent=2)
    
    print(f"项目分析完成:")
    print(f"• 项目名称: {project_info['project_name']}")
    print(f"• 文件总数: {project_info['total_files']}")
    print(f"• 代码行数: {project_info['total_lines']}")
    print(f"• 文件类型: {', '.join([f'{k}({v})' for k, v in project_info['file_types'].items()])}")
    print(f"• 详细信息已保存到: {project_info_path}")
    
    # 步骤2: 使用CodeQL进行安全分析
    print(f"\n[2/3] 正在使用CodeQL进行安全分析...")
    
    # 自动检测语言
    detected_lang = detect_language(project_path)
    if not detected_lang:
        print("无法自动检测项目语言，请手动指定")
        return
    
    print(f"• 检测到项目主要语言: {detected_lang}")
    
    # 进行CodeQL分析
    codeql_output = os.path.join(OUTPUT_DIR, f"codeql_results_{timestamp}.sarif")
    codeql_results = call_codeql(project_path, output_path=codeql_output, language=detected_lang)
    
    # 保存CodeQL结果摘要
    codeql_summary_path = os.path.join(OUTPUT_DIR, f"codeql_summary_{timestamp}.json")
    with open(codeql_summary_path, 'w', encoding='utf-8') as f:
        json.dump(codeql_results, f, ensure_ascii=False, indent=2)
    
    print(f"CodeQL分析完成")
    
    # 统计问题数量和严重程度
    if isinstance(codeql_results, list) and len(codeql_results) > 0:
        if isinstance(codeql_results[0], str):
            print(f"• {codeql_results[0]}")
        else:
            # 统计严重程度
            severity_count = {"高": 0, "中": 0, "低": 0}
            for item in codeql_results:
                severity = item.get("severity", "警告")
                if "高" in severity or "critical" in severity.lower() or "high" in severity.lower():
                    severity_count["高"] += 1
                elif "中" in severity or "medium" in severity.lower():
                    severity_count["中"] += 1
                else:
                    severity_count["低"] += 1
            
            print(f"• 发现 {len(codeql_results)} 个潜在问题")
            print(f"• 严重程度: 高风险({severity_count['高']}), 中风险({severity_count['中']}), 低风险({severity_count['低']})")
            
            # 显示前5个最严重的问题
            if severity_count["高"] > 0:
                print("\n最严重的问题:")
                count = 0
                for item in codeql_results:
                    severity = item.get("severity", "")
                    if "高" in severity or "critical" in severity.lower() or "high" in severity.lower():
                        print(f"  [{count+1}] {item.get('path')}:{item.get('line')} - {item.get('message')[:100]}...")
                        count += 1
                        if count >= 5:
                            break
    else:
        print("• 未发现安全问题")
    
    print(f"• 详细结果已保存到: {codeql_output}")
    
    # 步骤3: 使用大模型进行综合分析
    print(f"\n[3/3] 正在使用大模型进行综合分析...")
    
    # 准备提示词
    prompt = f"""你是一个代码安全分析专家，请根据以下项目信息和CodeQL分析结果，对该项目进行全面的安全评估:

项目名称: {project_info['project_name']}
项目路径: {project_info['project_path']}
文件总数: {project_info['total_files']}
代码行数: {project_info['total_lines']}
主要语言: {detected_lang}

CodeQL分析发现了 {len(codeql_results) if isinstance(codeql_results, list) else 0} 个潜在问题。

请提供以下内容:
1. 项目安全总体评分(1-10分)
2. 主要安全问题分类和严重程度
3. 针对性修复建议
4. 安全加固方案

请以中文回答，回答要简洁专业。
"""
    
    ai_analysis = query_model(model, tokenizer, prompt)
    
    # 保存大模型分析结果
    ai_analysis_path = os.path.join(OUTPUT_DIR, f"ai_analysis_{timestamp}.txt")
    with open(ai_analysis_path, 'w', encoding='utf-8') as f:
        f.write(ai_analysis)
    
    print(f"\n大模型安全评估:")
    print("-" * 40)
    print(ai_analysis)
    print("-" * 40)
    print(f"\n完整分析报告已保存到: {ai_analysis_path}")
    
    print("\n"+"="*50)
    print("分析完成！全部结果已保存到 results 目录")
    print("="*50)

def main():
    """主程序入口"""
    # 检查参数
    if len(sys.argv) < 2:
        print("用法: python mcp.py <项目路径>")
        return
    
    project_path = sys.argv[1]
    if not os.path.exists(project_path):
        print(f"错误: 项目路径 {project_path} 不存在")
        return
    
    # 加载模型
    model, tokenizer = load_model()
    
    # 处理项目
    process_project(project_path, model, tokenizer)

if __name__ == "__main__":
    main() 