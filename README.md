# acemcp-relay

Go HTTP 反向代理服务，用于中继请求到 Augment API。基于 Gin 框架构建，支持标准 HTTP 请求转发和 SSE（Server-Sent Events）流式传输。

## 功能特性

- **API 请求代理**：将客户端请求转发到 Augment API，支持多个预定义的 API 路径
- **SSE 流式传输**：支持 `/chat-stream` 和 `/prompt-enhancer` 端点的实时流式响应
- **API Key 认证**：基于 Bearer Token 的认证中间件，通过 PostgreSQL 存储 API Key，Redis 缓存加速验证
- **请求日志**：自动记录每个请求的状态、耗时、来源 IP 等信息到 PostgreSQL
- **错误追踪**：异步记录代理层和上游服务的错误详情
- **隐私保护**：对 `/get-models` 响应中的用户敏感信息（邮箱、ID、租户等）进行脱敏处理
- **使用排行榜**：定时统计 `/agents/codebase-retrieval` 端点的用户请求量排行榜（每 30 分钟更新）
- **请求验证**：对 `/chat-stream` 端点的请求体进行严格校验（mode、system_prompt、message 前缀）
- **安全拦截**：`/record-request-events` 和 `/report-error` 请求不转发到上游，避免被追踪

## 支持的 API 路径

### 标准代理路径

| 路径 | 说明 |
|------|------|
| `/get-models` | 获取模型列表（响应会脱敏） |
| `/agents/list-remote-tools` | 列出远程工具 |
| `/find-missing` | 查找缺失资源 |
| `/batch-upload` | 批量上传 |
| `/checkpoint-blobs` | 检查点数据 |
| `/agents/codebase-retrieval` | 代码库检索 |
| `/record-request-events` | 记录请求事件（拦截，不转发） |
| `/report-error` | 上报错误（拦截，不转发） |

### SSE 流式路径

| 路径 | 说明 |
|------|------|
| `/chat-stream` | 聊天流式传输（有请求体校验） |
| `/prompt-enhancer` | Prompt 增强 |

## 技术栈

- **语言**：Go 1.25
- **Web 框架**：Gin
- **数据库**：PostgreSQL（请求日志、排行榜、API Key 存储）
- **缓存**：Redis（API Key 缓存）
- **依赖管理**：Go Modules

## 前置要求

- Go 1.25+
- PostgreSQL
- Redis

## 快速开始

### 1. 克隆项目

```bash
git clone <repository-url>
cd acemcp-relay
```

### 2. 安装依赖

```bash
go mod download
```

### 3. 配置环境变量

复制示例配置文件并根据实际情况修改：

```bash
cp .env.example .env
```

### 4. 运行

```bash
go run main.go
```

### 5. 构建

```bash
go build -o acemcp-relay .
```

## 环境变量配置

通过 `.env` 文件或系统环境变量配置，所有变量均有默认值。

### 服务配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SERVER_ADDR` | 服务监听地址 | `127.0.0.1:8080` |

### Augment API 配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `AUGMENT_API_URL` | Augment API 上游地址 | （空） |
| `AUGMENT_API_TOKEN` | Augment API 认证 Token | （空） |

### PostgreSQL 配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `DB_HOST` | 数据库主机 | `localhost` |
| `DB_PORT` | 数据库端口 | `5432` |
| `DB_USER` | 数据库用户名 | `postgres` |
| `DB_PASSWORD` | 数据库密码 | （空） |
| `DB_NAME` | 数据库名称 | `postgres` |

### Redis 配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `REDIS_PORT` | Redis 端口 | `6379` |
| `API_KEY_CACHE_TTL` | API Key 缓存过期时间（Go duration 格式） | `30m` |

> `API_KEY_CACHE_TTL` 支持 Go `time.ParseDuration` 格式，例如 `30m`、`1h`、`2h30m`。

## 数据库表结构

服务启动时会自动迁移创建以下表：

- **`request_logs`**：请求日志，记录每个请求的用户、路径、状态码、耗时等
- **`error_details`**：错误详情，关联到 request_logs，区分代理层（proxy）和上游（upstream）错误
- **`leaderboard`**：每日用户请求量排行榜

## 日志

服务日志同时输出到控制台和 `gin.log` 文件。
