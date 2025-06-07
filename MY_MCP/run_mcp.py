import sys
import os
import subprocess
import argparse

def main():
    """
    MCP启动器：支持本地模式和API模式
    """
    parser = argparse.ArgumentParser(description="MCP代码安全分析系统启动器")
    
    # 添加命令行参数
    parser.add_argument("--mode", choices=["local", "api"], default="local",
                        help="运行模式：local=本地命令行模式，api=API服务模式")
    parser.add_argument("--host", default="127.0.0.1", help="API服务主机地址")
    parser.add_argument("--port", type=int, default=8000, help="API服务端口")
    parser.add_argument("--path", help="要分析的项目路径(仅本地模式)")
    parser.add_argument("--query", help="安全扫描需求，例如'SQL注入'、'CVE-2021-1234'等(仅本地模式)")
    
    args = parser.parse_args()
    
    # 根据模式选择启动不同的组件
    if args.mode == "local":
        print("以本地命令行模式启动MCP...")
        if args.path:
            # 如果提供了路径，直接进入分析模式
            import mcp_local
            mcp = mcp_local.MCPLocal()
            # 构建用户输入，包含路径和查询需求
            user_input = f"分析项目 {args.path}"
            if args.query:
                user_input += f" 检查{args.query}"
            mcp.process_project(args.path, user_input)
        else:
            # 否则进入交互模式
            import mcp_local
            mcp = mcp_local.MCPLocal()
            mcp.start_chat_mode()
    else:
        print(f"以API服务模式启动MCP（地址：{args.host}:{args.port}）...")
        try:
            # 使用uvicorn启动FastAPI服务
            import uvicorn
            uvicorn.run("mcp_api:app", host=args.host, port=args.port, reload=True)
        except ImportError:
            print("错误：未安装uvicorn。请使用pip安装：pip install uvicorn")
            sys.exit(1)
        except Exception as e:
            print(f"启动API服务失败：{str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main() 