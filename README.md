# YOP MCP - Java implementation

## 项目简介

YOP MCP 是一个易宝支付开放平台密钥工具的MCP服务。

## 功能特点

- 支持生成RSA、SM2类型的密钥
- 支持下载并激活CFCA证书

## 适用场景

- 对接易宝开放平台

## 系统要求

- Java 21或更高版本
- Maven 3.8或更高版本

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/yop-platform/yop-mcp-java.git
```

### 2. 构建项目

```bash
cd yop-mcp-java
mvn clean package
```

### 3. 配置MCP Server

- STDIO 模式
  创建或编辑MCP配置文件，添加以下配置：

```json
{
  "mcpServers": {
    "yop-mcp-java": {
      "command": "java",
      "args": [
        "-Dspring.ai.mcp.server.stdio=true",
        "-Dspring.main.web-application-type=none",
        "-Dlogging.pattern.console=",
        "-jar",
        "/your absolute path/target/yop-mcp-java-1.0.0-SNAPSHOT.jar"
      ]
    }
  }
}
```

