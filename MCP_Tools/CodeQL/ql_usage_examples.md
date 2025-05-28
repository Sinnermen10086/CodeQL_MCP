# CodeQL 查询用法示例

## 1. 套件（QLS）用法

- 适用于全量安全与质量分析
- 示例路径：`python/ql/src/codeql-suites/python-security-and-quality.qls`
- 调用命令：

```shell
codeql database analyze <db-path> python/ql/src/codeql-suites/python-security-and-quality.qls --format=sarif-latest --output=output.sarif
```

## 2. 单条规则（QL）用法

- 适用于指定漏洞类型分析，如命令注入、SQL注入等
- 示例路径：`python/ql/src/Security/CWE-078/CommandInjection.ql`
- 调用命令：

```shell
codeql database analyze <db-path> python/ql/src/Security/CWE-078/CommandInjection.ql --format=sarif-latest --output=output.sarif
```

## 3. 其它语言示例

- JavaScript 全量安全分析：
  - `javascript/ql/src/codeql-suites/javascript-security-and-quality.qls`
- Java 全量安全分析：
  - `java/ql/src/codeql-suites/java-security-and-quality.qls`
- C/C++ 全量安全分析：
  - `cpp/ql/src/codeql-suites/cpp-security-and-quality.qls`

## 4. 说明

- 所有路径均为相对于 codeql-main/ql 目录的相对路径。
- 你可以通过自动扫描函数获取所有可用的 QLS/QL 路径。
- 推荐优先使用 QLS 套件，针对特定需求可用单条 QL 规则。 
 