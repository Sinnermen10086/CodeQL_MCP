"""
MCP工具集合，用于项目分析和安全扫描
"""
import os

# 确保结果目录存在
if not os.path.exists("results"):
    os.makedirs("results", exist_ok=True)