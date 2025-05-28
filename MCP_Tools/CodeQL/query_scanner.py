import os
import glob

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
        qls_files = glob.glob(os.path.join(lang_dir, "codeql-suites", "*.qls"))
        ql_files = glob.glob(os.path.join(lang_dir, "Security", "**", "*.ql"), recursive=True)
        all_queries[language] = {
            "qls": [os.path.relpath(f, codeql_queries_root) for f in qls_files],
            "ql": [os.path.relpath(f, codeql_queries_root) for f in ql_files]
        }
    return all_queries

if __name__ == "__main__":
    codeql_root = r"E:\\codeql\\codeql-main"
    queries = collect_all_queries(codeql_root)
    import json
    print(json.dumps(queries, indent=2, ensure_ascii=False)) 