import os
import sys
import json
import time
import torch
import glob
import re
import subprocess
from transformers import AutoModelForCausalLM, AutoTokenizer
from MCP_Tools.project_analyzer import analyze_project
from MCP_Tools.CodeQL.codeql_wrapper import call_codeql, get_available_languages, get_available_queries, detect_language

# ------ 配置区 ------ #
MODEL_PATH = "E:\\DeepSeek 1.5B"  # 模型路径
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
OUTPUT_DIR = "results"  # 输出目录
CODEQL_PATH = "E:\\codeql"
CODEQL_QUERIES = r"E:\\codeql\\codeql-main"

class MCPLocal:
    def __init__(self):
        """初始化MCP本地测试模块"""
        print("初始化MCP本地测试模块...")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self.model = None
        self.tokenizer = None
        print("系统：请只用中文回答，不要输出英文。")
        
        # 多语言通用漏洞类型与规则文件映射表
        self.vuln_types = {
            "sql注入": {
                "keywords": ["sql注入", "sqlinjection", "sql_injection", "sql-injection", "cwe-089"],
                "ql_files": {
                    "python": ["python/ql/src/Security/CWE-089/SqlInjection.ql"],
                    "java": ["java/ql/src/queries/security/CWE-089/SqlInjection.ql"],
                    "javascript": ["javascript/ql/src/queries/security/CWE-089/SqlInjection.ql"],
                    "csharp": ["csharp/ql/src/queries/security/CWE-089/SqlInjection.ql"],
                    "cpp": ["cpp/ql/src/queries/security/CWE-089/SqlInjection.ql"],
                    "go": ["go/ql/src/queries/security/CWE-089/SqlInjection.ql"],
                    "ruby": ["ruby/ql/src/queries/security/cwe-089/SqlInjection.ql"],
                    "rust": ["rust/ql/src/queries/security/CWE-089/SqlInjection.ql"],
                    "swift": ["swift/ql/src/queries/security/CWE-089/SqlInjection.ql"]
                }
            },
            # ... 其他漏洞类型的定义与之前相同 ...
        }
        
    def load_model(self):
        """加载大模型"""
        if self.model is not None and self.tokenizer is not None:
            return self.model, self.tokenizer
            
        print("正在加载模型...", end="", flush=True)
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_PATH,
            device_map="auto",
            torch_dtype=torch.float16,
            trust_remote_code=True
        )
        self.model.eval()
        print(" 完成。")
        return self.model, self.tokenizer
    
    def query_model(self, prompt, max_tokens=1024):
        """向模型提交查询"""
        model, tokenizer = self.load_model()
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
    
    def normalize_path(self, path):
        """标准化路径，处理引号和反斜杠"""
        # 移除引号
        path = path.strip('"\'')
        # 确保路径分隔符正确
        return os.path.normpath(path)
    
    def is_valid_path(self, path):
        """检查路径是否有效"""
        try:
            path = self.normalize_path(path)
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
    
    def summarize_osv_reports(self, output_dir, timestamp=None):
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
    
    def summarize_sarif(self, sarif_path):
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
    
    def scan_project_for_vulnerabilities(self, project_path):
        """
        扫描项目代码，分析可能存在的漏洞类型
        """
        # 检测项目使用的框架、库和API
        frameworks = self.detect_frameworks(project_path)
        # 扫描危险API调用
        dangerous_apis = self.scan_dangerous_apis(project_path)
        # 扫描风险模式
        risk_patterns = self.scan_risk_patterns(project_path)
        
        # 综合分析，返回建议查询
        result = {
            "potential_vulnerabilities": [],
            "risk_score": 0,
            "recommended_queries": {}
        }
        
        # 根据检测到的框架、危险API和风险模式，推断可能的漏洞类型
        if any(api in dangerous_apis for api in ["execute", "executemany", "raw"]):
            result["potential_vulnerabilities"].append("sql_injection")
        
        if any(framework in frameworks for framework in ["flask", "django", "jinja2"]):
            if "render_template" in dangerous_apis or "render" in dangerous_apis:
                result["potential_vulnerabilities"].append("xss")
        
        if any(api in dangerous_apis for api in ["subprocess", "os.system", "exec"]):
            result["potential_vulnerabilities"].append("command_injection")
        
        # 此处添加更多的漏洞类型推断逻辑...
        
        # 根据推断的漏洞类型，推荐相应的查询
        languages = self.detect_project_languages(project_path)
        for lang in languages:
            result["recommended_queries"][lang] = []
            for vuln in result["potential_vulnerabilities"]:
                queries = self.get_queries_for_vulnerability(lang, vuln)
                result["recommended_queries"][lang].extend(queries)
        
        # 计算风险分数
        result["risk_score"] = self.calculate_risk_score(
            result["potential_vulnerabilities"], 
            dangerous_apis, 
            risk_patterns
        )
        
        return result

    def detect_frameworks(self, project_path):
        """检测项目使用的框架和库"""
        frameworks = []
        
        # 检查Python项目
        req_file = os.path.join(project_path, "requirements.txt")
        if os.path.exists(req_file):
            with open(req_file, "r") as f:
                content = f.read()
                if "flask" in content.lower():
                    frameworks.append("flask")
                if "django" in content.lower():
                    frameworks.append("django")
                if "jinja2" in content.lower():
                    frameworks.append("jinja2")
        
        # 检查Java项目
        pom_file = os.path.join(project_path, "pom.xml")
        if os.path.exists(pom_file):
            with open(pom_file, "r") as f:
                content = f.read()
                if "spring" in content.lower():
                    frameworks.append("spring")
                if "jakarta" in content.lower() or "javax" in content.lower():
                    frameworks.append("jakarta")
        
        # 添加更多框架检测逻辑...
        
        return frameworks

    def scan_dangerous_apis(self, project_path):
        """扫描项目中的危险API调用"""
        dangerous_apis = []
        
        # 简单实现：遍历所有代码文件，查找潜在危险API
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith((".py", ".java", ".js", ".cs", ".go", ".rb")):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                            # SQL注入相关API
                            if "execute(" in content or "query(" in content:
                                dangerous_apis.append("execute")
                            # 命令执行相关API
                            if "subprocess.run(" in content or "os.system(" in content:
                                dangerous_apis.append("os.system")
                            # XSS相关API
                            if "render_template(" in content:
                                dangerous_apis.append("render_template")
                            # 添加更多危险API检测...
                    except:
                        pass
        
        return dangerous_apis

    def scan_risk_patterns(self, project_path):
        """扫描项目中的风险代码模式"""
        risk_patterns = []
        
        # 简单实现：遍历所有代码文件，查找风险代码模式
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith((".py", ".java", ".js", ".cs", ".go", ".rb")):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                            # SQL拼接模式
                            if re.search(r'query\s*\+\s*["\']', content) or re.search(r'execute\([^)]*\+', content):
                                risk_patterns.append("sql_string_concat")
                            # 未过滤的用户输入
                            if re.search(r'request\.(args|form|json|data)', content) and re.search(r'render', content):
                                risk_patterns.append("unfiltered_user_input")
                            # 添加更多风险模式检测...
                    except:
                        pass
        
        return risk_patterns

    def get_queries_for_vulnerability(self, language, vulnerability):
        """根据语言和漏洞类型获取对应的查询"""
        for vuln, info in self.vuln_types.items():
            if vulnerability == vuln or vulnerability in [k.lower() for k in info["keywords"]]:
                return info["ql_files"].get(language.lower(), [])
        return []

    def calculate_risk_score(self, vulnerabilities, dangerous_apis, risk_patterns):
        """计算项目的风险分数"""
        score = 0
        
        # 根据潜在漏洞类型加分
        vuln_scores = {
            "sql_injection": 8,
            "xss": 7,
            "command_injection": 9,
            "path_traversal": 7,
            "ssrf": 8
        }
        
        for vuln in vulnerabilities:
            score += vuln_scores.get(vuln, 5)
        
        # 根据危险API和风险模式调整分数
        score += len(dangerous_apis) * 0.5
        score += len(risk_patterns) * 1.0
        
        # 归一化到1-10范围
        return min(max(score / 10, 1), 10)

    def detect_project_languages(self, project_path):
        """检测项目使用的编程语言"""
        languages = []
        extensions = {
            ".py": "python",
            ".java": "java",
            ".js": "javascript",
            ".ts": "javascript",
            ".cs": "csharp",
            ".go": "go",
            ".rb": "ruby",
            ".rs": "rust",
            ".c": "cpp",
            ".cpp": "cpp",
            ".swift": "swift"
        }
        
        for root, dirs, files in os.walk(project_path):
            for file in files:
                for ext, lang in extensions.items():
                    if file.endswith(ext) and lang not in languages:
                        languages.append(lang)
        
        return languages

    def filter_queries_by_keywords(self, available_queries, language, keywords):
        """
        根据关键字筛选合适的QL文件路径
        
        Args:
            available_queries: query_scanner返回的查询文件字典
            language: 目标语言，如'python', 'java'等
            keywords: 关键词列表，如['信息泄露', 'information', 'leak']
        
        Returns:
            匹配到的QL文件路径，按匹配度排序
        """
        if not language or language not in available_queries:
            return None, "未找到指定语言的规则库"
        
        # 转换keywords为小写
        keywords_lower = [k.lower() for k in keywords]
        
        # 获取指定语言的所有QL文件
        all_ql_files = available_queries[language].get("ql", [])
        
        # 建立匹配结果列表，存储(ql_path, score)元组
        matches = []
        
        # 打印调试信息
        print(f"• 查找语言: {language}, 关键词: {keywords_lower}")
        print(f"• 可用的QL文件数量: {len(all_ql_files)}")
        if all_ql_files:
            print(f"• 样本QL文件: {all_ql_files[:2]}")
        
        for ql_path in all_ql_files:
            ql_path_lower = ql_path.lower()
            
            # 初始分数
            score = 0
            
            # 1. 文件名完全匹配某关键词得高分
            file_name = os.path.basename(ql_path_lower).split('.')[0]
            for kw in keywords_lower:
                if kw == file_name:
                    score += 100
                    print(f"• 文件名完全匹配: {ql_path} (score +100)")
                    break
            
            # 2. 文件名包含关键词得中高分
            for kw in keywords_lower:
                if kw in file_name:
                    score += 50
                    print(f"• 文件名部分匹配: {ql_path} (score +50)")
                    break
            
            # 3. 路径包含关键词得中分
            for kw in keywords_lower:
                if kw in ql_path_lower:
                    score += 30
                    print(f"• 路径包含关键词: {ql_path} (score +30)")
                    break
            
            # 4. 特殊规则 - CWE编号匹配
            cwe_mapping = {
                "信息泄露": ["cwe-209", "cwe-200"],
                "sql注入": ["cwe-089"],
                "xss": ["cwe-079"],
                "命令注入": ["cwe-078"],
                "路径遍历": ["cwe-022"],
                "ssrf": ["cwe-918"],
                "反序列化": ["cwe-502"],
                "文件上传": ["cwe-434"],
                "ldap注入": ["cwe-090"],
                "代码注入": ["cwe-094"],
                "日志注入": ["cwe-117"],
                "重定向": ["cwe-601"],
                "xxe": ["cwe-611"],
                "nosql注入": ["cwe-943"],
                "密码硬编码": ["cwe-798"],
                "密码弱加密": ["cwe-327"]
            }
            
            for keyword, cwe_codes in cwe_mapping.items():
                if keyword in keywords_lower:
                    for cwe in cwe_codes:
                        if cwe in ql_path_lower:
                            score += 80
                            print(f"• CWE匹配: {ql_path} 包含 {cwe} (score +80)")
                            break
            
            # 5. 安全相关文件加分
            if "security" in ql_path_lower:
                score += 20
            
            # 6. 针对特定术语加分
            special_terms = {
                "信息泄露": ["exposure", "leak", "disclosure", "information", "stacktrace", "sensitive"],
                "sql注入": ["sqlinjection", "sqli", "database"],
                "xss": ["cross-site", "xss", "script"],
                "命令注入": ["command", "exec", "shell", "injection"],
                "路径遍历": ["path", "traversal", "directory"],
                "ssrf": ["server", "request", "forgery"],
                "反序列化": ["deserial", "marshal", "pickle"],
                "文件上传": ["upload", "file"],
                "xxe": ["xxe", "xml", "external", "entity"]
            }
            
            for keyword, terms in special_terms.items():
                if keyword in keywords_lower:
                    for term in terms:
                        if term in ql_path_lower:
                            score += 40
                            print(f"• 特殊术语匹配: {ql_path} 包含 {term} (score +40)")
                            break
            
            # 只保留有得分的路径
            if score > 0:
                matches.append((ql_path, score))
        
        # 按分数降序排序
        matches.sort(key=lambda x: x[1], reverse=True)
        
        # 打印匹配结果
        print(f"• 匹配结果数量: {len(matches)}")
        if matches:
            print(f"• 最佳匹配: {matches[0][0]} (score: {matches[0][1]})")
            for i, (path, score) in enumerate(matches[:5]):
                print(f"  {i+1}. {path} (score: {score})")
        
        # 返回最匹配的结果
        if matches:
            return matches[0][0], f"关键字匹配度: {matches[0][1]}"
        
        # 兜底返回对应语言的security-and-quality.qls
        qls_files = available_queries[language].get("qls", [])
        for qls in qls_files:
            if "security-and-quality" in qls.lower():
                return qls, "未找到精确匹配，使用全量安全与质量分析套件"
        
        return None, "未找到合适的查询文件"

    def choose_query_file(self, user_input, available_queries, language):
        """根据用户输入关键字精确筛选QL路径"""
        # 从用户输入提取关键词
        user_input_lower = user_input.lower()
        
        # 预定义的关键词映射
        keyword_mapping = {
            "sql注入": ["sql注入", "sqlinjection", "sql_injection", "sql-injection"],
            "xss": ["xss", "跨站脚本", "cross-site-scripting"],
            "命令注入": ["命令注入", "command_injection", "commandinjection"],
            "路径遍历": ["路径遍历", "path_traversal", "目录穿越"],
            "ssrf": ["ssrf", "服务器请求伪造", "server-side-request-forgery"],
            "信息泄露": ["信息泄露", "information_leak", "information-disclosure", "敏感信息"],
            "反序列化": ["反序列化", "deserialization", "不安全反序列化"],
            "文件上传": ["文件上传", "fileupload", "unrestricted-file-upload"],
            "ldap注入": ["ldap注入", "ldap_injection", "ldapinjection"],
            "代码注入": ["代码注入", "code_injection", "codeinjection"],
            "日志注入": ["日志注入", "log_injection", "loginjection"],
            "重定向": ["重定向", "url_redirect", "urlredirect"],
            "xxe": ["xxe", "xml外部实体", "xml external entity"],
            "nosql注入": ["nosql注入", "nosql_injection", "nosqlinjection"],
            "密码硬编码": ["密码硬编码", "hardcoded_credentials", "硬编码凭证"],
            "密码弱加密": ["密码弱加密", "weak_encryption", "弱加密算法"]
        }
        
        # 检查用户输入是否明确包含漏洞类型关键词
        has_specific_vuln_keyword = False
        for category, keywords in keyword_mapping.items():
            if any(kw in user_input_lower for kw in keywords):
                has_specific_vuln_keyword = True
                break
                
        # 如果用户明确指定了漏洞类型，则进行关键词匹配
        if has_specific_vuln_keyword:
            # 根据用户输入确定关键词
            selected_keywords = []
            for category, keywords in keyword_mapping.items():
                if any(kw in user_input_lower for kw in keywords):
                    selected_keywords.append(category)
                    selected_keywords.extend(keywords)
            
            print(f"• 提取到的漏洞关键词: {selected_keywords}")
            
            # 筛选匹配的查询文件
            query_path, reason = self.filter_queries_by_keywords(available_queries, language, selected_keywords)
            if query_path:
                return query_path, f"根据关键字筛选到专项规则: {reason}"
        else:
            # 如果没有明确的漏洞类型关键词，直接使用全量套件
            print("• 未检测到具体漏洞类型关键词，将使用全量安全分析套件")
            
            # 优先选择 security-and-quality 套件
            for q in available_queries.get(language, {}).get("qls", []):
                if "security-and-quality" in q.lower():
                    return q, "默认选择全量安全与质量分析套件"
            
            # 退化选择任何包含 security 的套件
            for q in available_queries.get(language, {}).get("qls", []):
                if "security" in q.lower():
                    return q, "默认选择安全相关分析套件"
        
        # 最后的兜底选择
        if available_queries.get(language, {}).get("qls"):
            return available_queries[language]["qls"][0], "默认选择第一个套件"
        if available_queries.get(language, {}).get("ql"):
            return available_queries[language]["ql"][0], "默认选择第一个规则"
        
        return None, "未找到合适的查询文件"
    
    def process_project(self, project_path, user_input=""):
        """项目分析主流程
        Args:
            project_path: 要分析的项目路径
            user_input: 用户原始输入，用于智能选择查询文件
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        print("="*50)
        print(f"开始分析项目: {project_path}")
        print("="*50)
        
        # 步骤0: 自动调用 OSV-Scanner 扫描依赖
        osv_report_path = os.path.join(OUTPUT_DIR, f"osv_report_{timestamp}.json")
        print(f"\n[0/3] 正在使用 OSV-Scanner 扫描项目依赖...")
        try:
            cmd = f'osv-scanner.exe scan source "{project_path}" --json --output "{osv_report_path}"'
            print(f"执行命令: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"OSV-Scanner 扫描完成，结果已保存到 {osv_report_path}")
            else:
                print(f"OSV-Scanner 扫描失败：{result.stderr}")
                simple_cmd = f'osv-scanner.exe scan source "{project_path}"'
                print(f"尝试简单命令: {simple_cmd}")
                simple_result = subprocess.run(simple_cmd, shell=True)
                if simple_result.returncode == 0:
                    print("简单命令扫描成功，但结果未保存到文件")
        except Exception as e:
            print(f"OSV-Scanner 执行异常: {e}")
        
        # 步骤1: 分析项目结构
        print(f"\n[1/3] 正在分析项目结构...")
        project_info = analyze_project(project_path)
        
        if "error" in project_info:
            print(f"错误: {project_info['error']}")
            return {"success": False, "error": project_info['error']}
        
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
            return {"success": False, "error": "无法自动检测项目语言"}
        
        print(f"• 检测到项目主要语言: {detected_lang}")
        
        # 自动选择 QLS 套件或 QL 单条规则
        query_path, reason = self.choose_query_file(user_input, project_info.get("available_queries", {}), detected_lang)
        if query_path:
            if not os.path.isabs(query_path):
                query_path = os.path.join(CODEQL_QUERIES, query_path)
            print(f"• 选择查询文件: {os.path.basename(query_path)}")
            print(f"• 选择原因: {reason}")
        else:
            print("• 未找到合适的查询文件，将使用默认的安全查询")
            query_path = None
        
        # 进行CodeQL分析
        codeql_output = os.path.join(OUTPUT_DIR, f"codeql_results_{timestamp}.sarif")
        codeql_results = call_codeql(project_path, query_path=query_path, output_path=codeql_output, language=detected_lang)
        
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
        
        # 读取OSV-Scanner依赖漏洞报告
        osv_findings = self.summarize_osv_reports(OUTPUT_DIR, timestamp)
        
        # 准备提示词
        prompt = f"""你是一个代码安全分析专家，请根据以下项目信息、代码分析结果和依赖漏洞扫描结果，对该项目进行全面的安全评估:

项目名称: {project_info['project_name']}
项目路径: {project_info['project_path']}
文件总数: {project_info['total_files']}
代码行数: {project_info['total_lines']}
主要语言: {detected_lang}

===== 代码安全分析结果 =====
代码分析发现了 {len(codeql_results) if isinstance(codeql_results, list) else 0} 个潜在问题。
{json.dumps(codeql_results[:10] if isinstance(codeql_results, list) else [], ensure_ascii=False, indent=2)}

===== 依赖安全分析结果 =====
依赖扫描发现了 {len(osv_findings)} 个漏洞。
{json.dumps(osv_findings[:10], ensure_ascii=False, indent=2)}

请提供以下内容:
1. 项目安全总体评分(1-10分)
2. 代码安全性分析
3. 依赖安全性分析
4. 综合风险评估
5. 修复和加固建议

请以中文回答，回答要简洁专业。
"""
        
        ai_analysis = self.query_model(prompt)
        
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
        
        # 返回分析结果
        return {
            "success": True,
            "timestamp": timestamp,
            "project_info": project_info,
            "codeql_results": codeql_results,
            "osv_findings": osv_findings,
            "ai_analysis": ai_analysis,
        }
    
    def start_chat_mode(self):
        """启动交互式聊天模式"""
        print("\n" + "="*50)
        print("欢迎使用MCP代码安全分析聊天模式")
        print("="*50)
        print("您可以：")
        print("1. 请求分析项目: 例如'分析项目 C:\\路径\\项目名'")
        print("2. 询问安全知识: 例如'什么是SQL注入？'")
        print("3. 退出: 输入'退出'或'exit'")
        print("="*50 + "\n")
        
        history = []
        
        while True:
            user_input = input("\n> ")
            
            if user_input.lower() in ["退出", "exit", "quit"]:
                print("感谢使用MCP，再见！")
                break
                
            # 提取路径并分析项目
            if "分析" in user_input and "项目" in user_input:
                path_match = re.search(r'["\'](.*?)["\']', user_input)
                if path_match:
                    project_path = path_match.group(1)
                else:
                    words = user_input.split()
                    potential_paths = [w for w in words if self.is_valid_path(w)]
                    if potential_paths:
                        project_path = potential_paths[0]
                    else:
                        print("未能识别有效的项目路径，请使用引号包围路径或提供完整路径")
                        continue
                
                print(f"正在分析项目：{project_path}")
                # 传递用户输入，以便选择合适的查询文件
                result = self.process_project(project_path, user_input)
                if result and not result.get("success", False):
                    print(f"分析失败: {result.get('error', '未知错误')}")
                continue
            
            # 一般问答
            prompt = f"""你是一个专业的代码安全分析助手。用户的问题是: {user_input}
            
如果是关于代码安全、漏洞类型或安全最佳实践的问题，请给出专业、准确、简洁的回答。
如果是其他无关问题，请礼貌地引导回安全领域的讨论。

请用中文回答，保持简洁专业。
"""
            response = self.query_model(prompt, max_tokens=512)
            print(response)
            history.append((user_input, response))

def main():
    """主函数"""
    print("MCP本地测试模块启动...")
    
    mcp = MCPLocal()
    
    if len(sys.argv) >= 3 and sys.argv[1] == "--analyze":
        # 分析模式
        project_path = sys.argv[2]
        if not os.path.exists(project_path):
            print(f"错误: 项目路径 '{project_path}' 不存在")
            sys.exit(1)
        mcp.process_project(project_path)
    else:
        # 交互式聊天模式
        mcp.start_chat_mode()

if __name__ == "__main__":
    main() 