# MCP 安全分析系统

MCP是一个本地大模型驱动的代码安全分析系统，结合了CodeQL静态分析和OSV-Scanner依赖漏洞扫描能力，为开发者提供一站式的代码安全分析服务。

## 功能特点

- 🚀 **智能关键词匹配**：自动从用户需求中提取关键词，精准匹配最合适的CodeQL规则
- 🔍 **多语言支持**：支持Python、Java、JavaScript、C/C++、C#、Go、Ruby等主流语言
- 🛡️ **漏洞分类全覆盖**：SQL注入、XSS、命令注入、信息泄露、路径遍历等常见漏洞类型
- 📊 **自然语言报告**：生成易懂的安全分析报告，避免晦涩的技术术语
- 🧠 **大模型驱动**：本地部署大模型，保证数据隐私与分析效率

## 使用方法

### 通过命令行

```bash
# 基本使用
python mcp_local.py

# 在交互模式中，输入以下命令进行项目分析
分析项目 "E:\my_project\py_demo" sql注入
分析项目 "D:\code\java_demo" 检查XSS
分析项目 "C:\Projects\csharp_demo" 信息泄露
```

### 通过API调用

```python
import requests

# 同步分析
response = requests.post(
    "http://localhost:8000/analyze_sync",
    json={"project_path": "E:\\my_project\\py_demo"}
)
print(response.json()["report"])

# 上传zip分析
with open("project.zip", "rb") as f:
    response = requests.post(
        "http://localhost:8000/analyze_upload",
        files={"file": f}
    )
print(response.json()["report"])
```

## 专项漏洞检测指令

系统支持以下常见漏洞类型的专项检测：

* **SQL注入**: `分析项目 "E:\vuln_app" sql注入`
* **XSS**: `分析项目 "E:\vuln_app" xss`
* **命令注入**: `分析项目 "E:\vuln_app" 命令注入`
* **信息泄露**: `分析项目 "E:\vuln_app" 信息泄露`
* **路径遍历**: `分析项目 "E:\vuln_app" 路径遍历`
* **SSRF**: `分析项目 "E:\vuln_app" ssrf`
* **反序列化**: `分析项目 "E:\vuln_app" 反序列化`
* **XXE**: `分析项目 "E:\vuln_app" xxe`

## 系统要求

- Windows/Linux/macOS
- Python 3.8+
- CodeQL CLI
- OSV-Scanner (可选)
- 本地部署的大模型 (可配置路径)

## 项目结构

```
MCP/
├── mcp.py               # 命令行主程序
├── cli_chat.py          # 聊天模式入口
├── mcp_api.py           # API服务模块
├── run_mcp.py           # 统一启动器
├── requirements.txt     # 依赖库清单
├── MCP_Tools/           # 工具模块目录
│   ├── project_analyzer.py  # 项目分析工具
│   └── CodeQL/             # CodeQL相关模块
│       ├── codeql_wrapper.py  # CodeQL调用封装
│       └── codeql_schema.json # CodeQL参数模式定义
├── results/             # 分析结果输出目录
└── temp/                # 临时文件目录（用于API上传分析）
```

## 扩展功能

- 支持更多编程语言
- 添加更多安全规则
- 集成其他静态分析工具
- 实现图形用户界面
- 完善API文档（Swagger/ReDoc）

## 注意事项

- 确保CodeQL CLI正确安装并可在路径中访问
- 大型项目分析可能需要较长时间
- 分析结果仅供参考，建议由安全专家进行最终评估
- API模式下默认仅监听本地地址(127.0.0.1)，如需远程访问请修改host参数 