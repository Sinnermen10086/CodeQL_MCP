import os
import json
import re
from collections import Counter
from MCP_Tools.CodeQL.query_scanner import collect_all_queries

def get_file_info(file_path):
    """获取文件的基本信息"""
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        lines = content.count('\n') + 1
        return {
            "path": file_path,
            "size": file_size,
            "lines": lines,
            "content": content
        }
    except Exception as e:
        return {
            "path": file_path,
            "size": 0,
            "lines": 0,
            "error": str(e)
        }

def scan_project(project_path, max_files=100, file_extensions=None):
    """扫描项目结构，提取关键信息"""
    if not os.path.exists(project_path):
        return {"error": f"项目路径 {project_path} 不存在"}
    
    if file_extensions is None:
        file_extensions = ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.cs', '.go', '.rb', '.php']
    
    # 默认忽略的目录
    ignore_dirs = ['.git', '.svn', 'node_modules', 'venv', 'env', '__pycache__', 'bin', 'obj', 'build', 'dist']
    
    project_info = {
        "path": project_path,
        "name": os.path.basename(project_path),
        "files": [],
        "file_types": {},
        "total_files": 0,
        "total_size": 0,
        "total_lines": 0,
        "available_queries": None
    }
    
    file_counter = 0
    for root, dirs, files in os.walk(project_path):
        # 跳过忽略的目录
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            file_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            
            # 只处理指定的文件类型
            if ext not in file_extensions:
                continue
            
            # 文件类型统计
            project_info["file_types"][ext] = project_info["file_types"].get(ext, 0) + 1
            project_info["total_files"] += 1
            
            # 限制处理的文件数量
            if file_counter < max_files:
                file_info = get_file_info(file_path)
                project_info["files"].append(file_info)
                project_info["total_size"] += file_info.get("size", 0)
                project_info["total_lines"] += file_info.get("lines", 0)
                file_counter += 1
    
    # 自动扫描所有可用 QL/QLS 查询
    codeql_root = r"E:\\codeql\\codeql-main"
    if os.path.exists(codeql_root):
        project_info['available_queries'] = collect_all_queries(codeql_root)
    else:
        project_info['available_queries'] = {}
    
    return project_info

def extract_imports(project_info):
    """提取项目中的导入语句"""
    imports = {
        "python": [],
        "javascript": [],
        "java": [],
        "csharp": [],
        "cpp": []
    }
    
    for file in project_info["files"]:
        if "content" not in file:
            continue
            
        ext = os.path.splitext(file["path"])[1].lower()
        content = file["content"]
        
        # Python导入
        if ext == '.py':
            py_imports = re.findall(r'^\s*(?:import|from)\s+([^\s]+)', content, re.MULTILINE)
            imports["python"].extend(py_imports)
        
        # JavaScript/TypeScript导入
        elif ext in ['.js', '.ts']:
            js_imports = re.findall(r'(?:import|require)\s*\(?[\'"]([^\'"]+)[\'"]', content)
            imports["javascript"].extend(js_imports)
        
        # Java导入
        elif ext == '.java':
            java_imports = re.findall(r'import\s+([^;]+);', content)
            imports["java"].extend(java_imports)
        
        # C#导入
        elif ext == '.cs':
            cs_imports = re.findall(r'using\s+([^;]+);', content)
            imports["csharp"].extend(cs_imports)
        
        # C/C++导入
        elif ext in ['.c', '.cpp', '.h', '.hpp']:
            cpp_imports = re.findall(r'#include\s*[<"]([^>"]+)[>"]', content)
            imports["cpp"].extend(cpp_imports)
    
    # 统计导入频率
    for lang in imports:
        counter = Counter(imports[lang])
        imports[lang] = [{"name": name, "count": count} for name, count in counter.most_common()]
    
    return imports

def analyze_project(project_path, max_files=100):
    """分析项目并生成摘要信息"""
    project_info = scan_project(project_path, max_files)
    
    if "error" in project_info:
        return project_info
    
    # 提取导入信息
    imports = extract_imports(project_info)
    
    # 移除文件内容以减小结果大小
    for file in project_info["files"]:
        if "content" in file:
            del file["content"]
    
    # 项目摘要
    summary = {
        "project_name": project_info["name"],
        "project_path": project_info["path"],
        "total_files": project_info["total_files"],
        "total_size": project_info["total_size"],
        "total_lines": project_info["total_lines"],
        "file_types": project_info["file_types"],
        "imports": imports,
        "available_queries": project_info["available_queries"]
    }
    
    return summary 