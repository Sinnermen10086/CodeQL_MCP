# MCP (Model-driven Code Protection)

MCP是一个使用大模型驱动的代码安全分析工具，它能自动扫描项目结构，提取关键信息，并使用CodeQL进行静态安全分析。

## 功能特点

- 🔍 **项目结构分析**：自动扫描并分析项目文件结构、依赖关系
- 🛡️ **CodeQL安全分析**：利用CodeQL进行深度静态代码安全分析
- 🤖 **大模型评估**：使用大模型对安全扫描结果进行综合评估
- 📊 **安全报告生成**：生成详细的安全分析报告
- 💬 **交互式问答**：通过聊天界面进行安全咨询

## 系统要求

- Python 3.8+
- PyTorch 1.12+
- Transformers 4.20+
- CodeQL CLI (已安装并配置)

## 安装与配置

1. 确保已安装CodeQL CLI，并下载CodeQL标准库：
   - CodeQL CLI路径：`E:\codeql`
   - CodeQL 标准库路径：`E:\codeql\codeql-main`

2. 安装依赖库：
   ```
   pip install torch transformers
   ```

3. 配置模型路径：
   在`mcp.py`和`cli_chat.py`中设置正确的模型路径。

## 使用方法

### 1. 命令行模式分析项目

```
python mcp.py <项目路径>
```

这将执行：
1. 项目结构分析
2. CodeQL安全扫描
3. 大模型安全评估
4. 生成安全报告

所有结果将保存在`results`目录下。

### 2. 交互式聊天模式

```
python cli_chat.py
```

在聊天模式中，您可以：
- 请求对特定项目进行分析
- 执行CodeQL扫描
- 咨询安全相关问题

示例对话：
- "分析项目 C:\Projects\MyApp"
- "扫描 C:\Projects\MyApp 有没有SQL注入漏洞"
- "什么是跨站脚本攻击？如何防范？"

## 项目结构

```
MCP/
├── mcp.py               # 主程序入口
├── cli_chat.py          # 聊天模式入口
├── MCP_Tools/           # 工具模块目录
│   ├── project_analyzer.py  # 项目分析工具
│   └── CodeQL/             # CodeQL相关模块
│       ├── codeql_wrapper.py  # CodeQL调用封装
│       └── codeql_schema.json # CodeQL参数模式定义
└── results/             # 分析结果输出目录
```

## 扩展功能

- 支持更多编程语言
- 添加更多安全规则
- 集成其他静态分析工具
- 实现图形用户界面

## 注意事项

- 确保CodeQL CLI正确安装并可在路径中访问
- 大型项目分析可能需要较长时间
- 分析结果仅供参考，建议由安全专家进行最终评估 