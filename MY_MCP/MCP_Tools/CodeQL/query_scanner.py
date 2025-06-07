import os
import glob
import re

def collect_all_queries(codeql_queries_root):
    """
    自动收集所有语言下的 QLS 套件和 QL 单条规则路径。
    返回格式：
    {
        'python': {
            'qls': [...],
            'ql': [...]
        },
        ...
    }
    """
    all_queries = {}
    for language in os.listdir(codeql_queries_root):
        lang_dir = os.path.join(codeql_queries_root, language, "ql", "src")
        if not os.path.isdir(lang_dir):
            continue
        
        # 收集所有QLS套件文件
        qls_files = glob.glob(os.path.join(lang_dir, "codeql-suites", "*.qls"))
        
        # 收集所有QL单条规则，不仅限于Security目录
        ql_files = []
        
        # 1. 收集Security目录下的所有QL文件（安全相关）
        security_qls = glob.glob(os.path.join(lang_dir, "Security", "**", "*.ql"), recursive=True)
        ql_files.extend(security_qls)
        
        # 2. 收集其他目录下的所有QL文件
        for root, dirs, files in os.walk(lang_dir):
            # 排除已经处理过的Security目录
            if "Security" in root.split(os.path.sep):
                continue
            
            # 排除codeql-suites目录
            if "codeql-suites" in root.split(os.path.sep):
                continue
                
            # 添加该目录下的所有QL文件
            for file in files:
                if file.endswith(".ql"):
                    ql_files.append(os.path.join(root, file))
        
        # 按类别组织QL文件
        categorized_qls = {}
        for ql_file in ql_files:
            rel_path = os.path.relpath(ql_file, codeql_queries_root)
            
            # 提取分类（基于路径）
            path_parts = rel_path.split(os.path.sep)
            if "Security" in path_parts:
                category = "Security"
            elif "experimental" in path_parts:
                category = "Experimental"
            elif "semmle" in path_parts:
                category = "Semmle"
            else:
                # 尝试从src之后的第一个目录名推断类别
                try:
                    src_index = path_parts.index("src")
                    if src_index + 1 < len(path_parts):
                        category = path_parts[src_index + 1]
                    else:
                        category = "Other"
                except ValueError:
                    category = "Other"
            
            # 添加到分类字典
            if category not in categorized_qls:
                categorized_qls[category] = []
            categorized_qls[category].append(rel_path)
        
        all_queries[language] = {
            "qls": [os.path.relpath(f, codeql_queries_root) for f in qls_files],
            "ql_by_category": categorized_qls,
            "ql": [os.path.relpath(f, codeql_queries_root) for f in ql_files]  # 保留完整列表以兼容现有代码
        }
    
    return all_queries

def get_query_metadata(codeql_queries_root, query_path):
    """
    读取QL文件的元数据信息（如描述、严重性等）
    
    Args:
        codeql_queries_root: CodeQL查询库根目录
        query_path: 相对于根目录的查询文件路径
    
    Returns:
        包含元数据的字典
    """
    metadata = {
        "name": os.path.basename(query_path),
        "path": query_path,
        "description": "",
        "severity": "未知",
        "tags": []
    }
    
    full_path = os.path.join(codeql_queries_root, query_path)
    if not os.path.exists(full_path):
        return metadata
    
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # 提取查询描述
            desc_match = re.search(r'\*\s*@description\s*(.*?)(?:\n\s*\*|$)', content, re.DOTALL)
            if desc_match:
                metadata["description"] = desc_match.group(1).strip()
            
            # 提取严重性
            severity_match = re.search(r'\*\s*@severity\s*(.*?)(?:\n\s*\*|$)', content)
            if severity_match:
                metadata["severity"] = severity_match.group(1).strip()
            
            # 提取标签
            tags_match = re.search(r'\*\s*@tags\s*(.*?)(?:\n\s*\*|$)', content)
            if tags_match:
                tags = tags_match.group(1).strip()
                metadata["tags"] = [tag.strip() for tag in tags.split(",")]
    except Exception as e:
        metadata["error"] = str(e)
    
    return metadata

if __name__ == "__main__":
    codeql_root = r"E:\\codeql\\codeql-main"
    queries = collect_all_queries(codeql_root)
    import json
    print(json.dumps(queries, indent=2, ensure_ascii=False)) 