"""
CodeQL工具模块，用于与CodeQL CLI交互并进行安全分析
"""

from .codeql_wrapper import call_codeql, get_available_languages, get_available_queries, detect_language
from .query_scanner import collect_all_queries, get_query_metadata

__all__ = [
    'call_codeql', 'get_available_languages', 'get_available_queries', 
    'detect_language', 'collect_all_queries', 'get_query_metadata'
]