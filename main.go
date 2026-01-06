package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// 从环境变量加载的配置
var (
	serverAddr      string
	augmentAPIURL   string
	augmentAPIToken string
	dbHost          string
	dbPort          int
	dbUser          string
	dbPassword      string
	dbName          string
)

const (
	// Context keys
	ContextKeyUserID    = "user_id"
	ContextKeyStartTime = "start_time"
	ContextKeyLogID     = "log_id"

	// 请求状态
	StatusPending   = "pending"
	StatusCompleted = "completed"

	// Leaderboard 配置
	LeaderboardUpdateInterval = 30 * time.Minute
	LeaderboardPath           = "/agents/codebase-retrieval"
	LeaderboardTopN           = 10
	LeaderboardTimezone       = "Asia/Shanghai"
)

var allowedPaths = []string{
	"/get-models",
	"/agents/list-remote-tools",
	"/find-missing",
	"/batch-upload",
	"/checkpoint-blobs",
	"/agents/codebase-retrieval",
	"/record-request-events",
	"/report-error",
}

var ssePaths = []string{
	"/chat-stream",
	"/prompt-enhancer",
}

// ChatStreamRequest 用于验证 /chat-stream 请求
type ChatStreamRequest struct {
	Message      string  `json:"message"`
	Mode         string  `json:"mode"`
	SystemPrompt *string `json:"system_prompt"`
}

const PROMPT_ENHANCER_MESSAGE_PREFIX = "⚠️ NO TOOLS ALLOWED ⚠️\n\nHere is an instruction that I'd like to give you, but it needs to be improved. Rewrite and enhance this instruction to make it clearer, more specific, less ambiguous, and correct any mistakes. Do not use any tools: reply immediately with your answer, even if you're not sure. Consider the context of our conversation history when enhancing the prompt. If there is code in triple backticks (```) consider whether it is a code sample and should remain unchanged.Reply with the following format:\n\n### BEGIN RESPONSE ###\nHere is an enhanced version of the original instruction that is more specific and clear:\n<augment-enhanced-prompt>enhanced prompt goes here</augment-enhanced-prompt>\n\n### END RESPONSE ###\n\nHere is my original instruction:\n\n"

// 请求头过滤：Host、Authorization、hop-by-hop 头以及反代相关头
var skipRequestHeaders = map[string]bool{
	"Host":              true,
	"Authorization":     true,
	"Content-Length":    true, // 由 Go http 库根据实际请求体自动计算
	"Connection":        true, // hop-by-hop
	"Keep-Alive":        true, // hop-by-hop
	"Te":                true, // hop-by-hop
	"Upgrade":           true, // hop-by-hop
	"Proxy-Connection":  true, // 非标准代理头
	"X-Forwarded-For":   true, // 反代相关
	"X-Forwarded-Proto": true,
	"X-Forwarded-Host":  true,
	"X-Forwarded-Port":  true,
	"X-Real-Ip":         true,
	"X-Original-Uri":    true,
	"Via":               true,
}

// 响应头过滤：hop-by-hop 头，代理不应转发
var skipResponseHeaders = map[string]bool{
	"Connection":          true, // hop-by-hop
	"Keep-Alive":          true, // hop-by-hop
	"Transfer-Encoding":   true, // hop-by-hop
	"Te":                  true, // hop-by-hop
	"Trailer":             true, // hop-by-hop
	"Upgrade":             true, // hop-by-hop
	"Proxy-Authorization": true, // 代理认证相关
	"Proxy-Authenticate":  true,
	"Content-Length":      true, // 由 Gin 根据实际响应体大小自动设置
	"Content-Encoding":    true, // 响应体已被 http.Client 解码，避免不匹配
	"Alt-Svc":             true, // HTTP/3 替代服务声明，对代理无意义
}

// generateRandomHex 生成指定长度的随机十六进制字符串
func generateRandomHex(length int) string {
	randBytes := make([]byte, length/2)
	rand.Read(randBytes)
	return hex.EncodeToString(randBytes)
}

// 常用邮箱后缀
var emailDomains = []string{
	"gmail.com", "outlook.com", "hotmail.com", "yahoo.com",
	"icloud.com", "protonmail.com", "qq.com", "163.com",
}

// generateRandomEmail 生成随机邮箱地址
func generateRandomEmail() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 7) // 6位用户名 + 1位选择域名
	rand.Read(b)
	username := make([]byte, 6)
	for i := 0; i < 6; i++ {
		username[i] = chars[int(b[i])%len(chars)]
	}
	domain := emailDomains[int(b[6])%len(emailDomains)]
	return fmt.Sprintf("%s@%s", username, domain)
}

// generateRandomTenantName 生成随机租户名称 (格式: dxx-discoveryx)
func generateRandomTenantName() string {
	b := make([]byte, 2)
	rand.Read(b)
	num1 := int(b[0]) % 21 // 0-20
	num2 := int(b[1]) % 10 // 0-9
	return fmt.Sprintf("d%d-discovery%d", num1, num2)
}

// sanitizeGetModelsResponse 对 /get-models 响应进行隐私处理
func sanitizeGetModelsResponse(respBody []byte) []byte {
	var data map[string]interface{}
	if err := json.Unmarshal(respBody, &data); err != nil {
		return respBody // 解析失败，返回原始响应
	}

	if user, ok := data["user"].(map[string]interface{}); ok {
		user["id"] = uuid.New().String()
		user["email"] = generateRandomEmail()
		user["tenant_id"] = generateRandomHex(32)
		user["tenant_name"] = generateRandomTenantName()
		// created_at 保留原值
	}

	sanitized, err := json.Marshal(data)
	if err != nil {
		return respBody // 编码失败，返回原始响应
	}
	return sanitized
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
}

var sseHttpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true, // 禁用压缩以支持流式传输
	},
}

// 全局数据库连接
var db *sql.DB

// loadConfig 从 .env 文件加载配置
func loadConfig() {
	_ = godotenv.Load() // 忽略错误，允许使用环境变量

	serverAddr = getEnv("SERVER_ADDR", "127.0.0.1:8080")
	augmentAPIURL = getEnv("AUGMENT_API_URL", "")
	augmentAPIToken = getEnv("AUGMENT_API_TOKEN", "")
	dbHost = getEnv("DB_HOST", "localhost")
	dbPort = getEnvInt("DB_PORT", 5432)
	dbUser = getEnv("DB_USER", "postgres")
	dbPassword = getEnv("DB_PASSWORD", "")
	dbName = getEnv("DB_NAME", "postgres")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// initDB 初始化数据库连接
func initDB() error {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	if err = db.Ping(); err != nil {
		return err
	}

	// 自动迁移：创建 request_logs 表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS request_logs (
			id UUID PRIMARY KEY,
			user_id VARCHAR(255) NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			status_code INTEGER,
			request_path VARCHAR(512) NOT NULL,
			request_method VARCHAR(10) NOT NULL,
			request_timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			response_duration_ms BIGINT,
			client_ip VARCHAR(45) NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_request_logs_user_id ON request_logs(user_id);
		CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(request_timestamp);
		CREATE INDEX IF NOT EXISTS idx_request_logs_status ON request_logs(status);
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate request_logs table: %w", err)
	}

	// 自动迁移：创建 leaderboard 表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS leaderboard (
			id VARCHAR(32) PRIMARY KEY,
			date_str VARCHAR(10) NOT NULL,
			rank INTEGER NOT NULL,
			user_id VARCHAR(255) NOT NULL,
			request_count BIGINT NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_leaderboard_date ON leaderboard(date_str);

		-- 部分索引：加速 codebase-retrieval 统计查询
		CREATE INDEX IF NOT EXISTS idx_request_logs_codebase_retrieval
			ON request_logs(user_id, request_timestamp)
			WHERE request_path = '/agents/codebase-retrieval';
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate leaderboard table: %w", err)
	}

	// 自动迁移：创建 error_details 表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS error_details (
			id SERIAL PRIMARY KEY,
			request_id UUID NOT NULL REFERENCES request_logs(id),
			source VARCHAR(20) NOT NULL DEFAULT 'proxy',
			error TEXT NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_error_details_request_id ON error_details(request_id);
	`)
	if err != nil {
		return fmt.Errorf("failed to migrate error_details table: %w", err)
	}

	return nil
}

// authenticateRequest 验证请求的 Authorization header，返回 user_id
// 如果验证失败返回空字符串和 false
func authenticateRequest(c *gin.Context) (string, bool) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return "", false
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	hash := md5.Sum([]byte(token))
	tokenMD5 := hex.EncodeToString(hash[:])

	var userID string
	err := db.QueryRow("SELECT user_id FROM api_keys WHERE id = $1", tokenMD5).Scan(&userID)
	if err != nil {
		return "", false
	}

	return userID, true
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 记录请求开始时间
		startTime := time.Now()
		c.Set(ContextKeyStartTime, startTime)

		userID, ok := authenticateRequest(c)
		if !ok {
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			} else {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			}
			return
		}

		// 将 user_id 存入 context
		c.Set(ContextKeyUserID, userID)

		// 生成 UUID 并插入一条 pending 状态的日志记录
		logID := uuid.New().String()
		_, err := db.Exec(`
			INSERT INTO request_logs (id, user_id, status, request_path, request_method, request_timestamp, client_ip)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, logID, userID, StatusPending, c.Request.URL.Path, c.Request.Method, startTime, c.ClientIP())
		if err != nil {
			log.Printf("[ERROR] Failed to insert request log: %v", err)
		} else {
			c.Set(ContextKeyLogID, logID)
		}

		c.Next()
	}
}

// RequestLogEntry 请求日志记录
type RequestLogEntry struct {
	LogID            string
	StatusCode       int
	ResponseDuration time.Duration
}

// completeRequestLogAsync 异步更新请求日志状态为已完成
func completeRequestLogAsync(entry RequestLogEntry) {
	go func() {
		if entry.LogID == "" {
			return
		}
		durationMs := entry.ResponseDuration.Milliseconds()

		_, err := db.Exec(`
			UPDATE request_logs
			SET status = $1, status_code = $2, response_duration_ms = $3, updated_at = NOW()
			WHERE id = $4
		`, StatusCompleted, entry.StatusCode, durationMs, entry.LogID)

		if err != nil {
			log.Printf("[ERROR] Failed to update request log: %v", err)
		}
	}()
}

// saveErrorDetailsAsync 异步保存错误详情到数据库
// source: "proxy" 表示本地转发服务错误，"upstream" 表示上游服务错误
func saveErrorDetailsAsync(logID string, source string, errorMsg string) {
	if logID == "" || errorMsg == "" {
		return
	}
	go func() {
		_, err := db.Exec(`
			INSERT INTO error_details (request_id, source, error)
			VALUES ($1, $2, $3)
		`, logID, source, errorMsg)
		if err != nil {
			log.Printf("[ERROR] Failed to save error details: %v", err)
		}
	}()
}

// getRequestLogEntry 从 Gin context 提取日志数据
func getRequestLogEntry(c *gin.Context, statusCode int) RequestLogEntry {
	startTime, _ := c.Get(ContextKeyStartTime)
	logID, _ := c.Get(ContextKeyLogID)

	startTimeVal, ok := startTime.(time.Time)
	if !ok {
		startTimeVal = time.Now()
	}

	logIDVal, _ := logID.(string)

	return RequestLogEntry{
		LogID:            logIDVal,
		StatusCode:       statusCode,
		ResponseDuration: time.Since(startTimeVal),
	}
}

func validateChatStreamRequest(body []byte) error {
	var req ChatStreamRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("invalid JSON")
	}

	// 检查 mode 必须为 CHAT
	if req.Mode != "CHAT" {
		return fmt.Errorf("mode must be CHAT")
	}

	// 检查 system_prompt 必须为 null
	if req.SystemPrompt != nil {
		return fmt.Errorf("system_prompt must be null")
	}

	// 检查 message 必须以固定 prompt 开头（prompt-enhancer 功能）
	if !strings.HasPrefix(req.Message, PROMPT_ENHANCER_MESSAGE_PREFIX) {
		return fmt.Errorf("message must start with required prompt")
	}

	return nil
}

func proxyHandler(c *gin.Context) {
	// 拦截 /record-request-events 和 /report-error，不转发到上游，避免被 trace
	if c.Request.URL.Path == "/record-request-events" || c.Request.URL.Path == "/report-error" {
		c.JSON(http.StatusOK, gin.H{})
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusOK))
		return
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusBadRequest))
		return
	}

	targetURL := augmentAPIURL + c.Request.URL.Path

	req, err := http.NewRequestWithContext(c.Request.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusInternalServerError))
		return
	}

	req.Header.Set("Authorization", "Bearer "+augmentAPIToken)

	for key, values := range c.Request.Header {
		if skipRequestHeaders[key] {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(c.Request.Context().Err(), context.Canceled) {
			completeRequestLogAsync(getRequestLogEntry(c, 499))
			return
		}
		logID, _ := c.Get(ContextKeyLogID)
		logIDStr, _ := logID.(string)
		saveErrorDetailsAsync(logIDStr, "proxy", err.Error())
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "failed to forward request"})
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusBadGateway))
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		if skipResponseHeaders[key] {
			continue
		}
		for _, v := range values {
			c.Header(key, v)
		}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to read response body"})
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusInternalServerError))
		return
	}

	if resp.StatusCode >= 400 {
		logID, _ := c.Get(ContextKeyLogID)
		logIDStr, _ := logID.(string)
		saveErrorDetailsAsync(logIDStr, "upstream", string(respBody))
	}

	// 对 /get-models 成功响应进行隐私处理
	if c.Request.URL.Path == "/get-models" && resp.StatusCode == http.StatusOK {
		respBody = sanitizeGetModelsResponse(respBody)
	}

	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
	completeRequestLogAsync(getRequestLogEntry(c, resp.StatusCode))
}

func sseProxyHandler(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusBadRequest))
		return
	}

	// 验证 /chat-stream 请求内容
	if c.FullPath() == "/chat-stream" {
		if err = validateChatStreamRequest(body); err != nil {
			logID, _ := c.Get(ContextKeyLogID)
			logIDStr, _ := logID.(string)
			saveErrorDetailsAsync(logIDStr, "proxy", err.Error())
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "request validation failed"})
			completeRequestLogAsync(getRequestLogEntry(c, http.StatusForbidden))
			return
		}
	}

	targetURL := augmentAPIURL + c.Request.URL.Path

	req, err := http.NewRequestWithContext(c.Request.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusInternalServerError))
		return
	}

	req.Header.Set("Authorization", "Bearer "+augmentAPIToken)

	for key, values := range c.Request.Header {
		if skipRequestHeaders[key] {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	resp, err := sseHttpClient.Do(req)
	if err != nil {
		if errors.Is(c.Request.Context().Err(), context.Canceled) {
			completeRequestLogAsync(getRequestLogEntry(c, 499))
			return
		}
		logID, _ := c.Get(ContextKeyLogID)
		logIDStr, _ := logID.(string)
		saveErrorDetailsAsync(logIDStr, "proxy", err.Error())
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "failed to forward request: " + err.Error()})
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusBadGateway))
		return
	}
	defer resp.Body.Close()

	// 上游返回错误状态码时，直接转发错误响应（非流式）
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		logID, _ := c.Get(ContextKeyLogID)
		logIDStr, _ := logID.(string)
		saveErrorDetailsAsync(logIDStr, "upstream", string(respBody))
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
		completeRequestLogAsync(getRequestLogEntry(c, resp.StatusCode))
		return
	}

	// 透传上游响应头（过滤 hop-by-hop 头）
	for key, values := range resp.Header {
		if skipResponseHeaders[key] {
			continue
		}
		for _, v := range values {
			c.Header(key, v)
		}
	}

	// 写入响应头
	c.Writer.WriteHeaderNow()

	// 获取 Flusher 接口以支持实时刷新
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusOK))
		return
	}

	// 流式读取并转发
	reader := bufio.NewReader(resp.Body)
	for {
		select {
		case <-c.Request.Context().Done():
			completeRequestLogAsync(getRequestLogEntry(c, 499))
			return
		default:
			line, err := reader.ReadBytes('\n')
			if err != nil {
				completeRequestLogAsync(getRequestLogEntry(c, http.StatusOK))
				return
			}

			_, writeErr := c.Writer.Write(line)
			if writeErr != nil {
				completeRequestLogAsync(getRequestLogEntry(c, 499))
				return
			}

			flusher.Flush()
		}
	}
}

// updateLeaderboard 统计当天 codebase-retrieval 请求并更新排行榜
func updateLeaderboard() error {
	// 加载 Asia/Shanghai 时区
	loc, err := time.LoadLocation(LeaderboardTimezone)
	if err != nil {
		return fmt.Errorf("failed to load timezone: %w", err)
	}

	// 获取当天日期范围（Asia/Shanghai）
	now := time.Now().In(loc)
	dateStr := now.Format("2006-01-02")
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	dayEnd := dayStart.Add(24 * time.Hour)

	log.Printf("[LEADERBOARD] Updating leaderboard for %s", dateStr)

	// 查询当天 top N 用户（只统计 status_code=200 的成功请求）
	rows, err := db.Query(`
		SELECT user_id, COUNT(*) as cnt
		FROM request_logs
		WHERE request_path = $1
		  AND request_timestamp >= $2
		  AND request_timestamp < $3
		  AND status_code = 200
		GROUP BY user_id
		ORDER BY cnt DESC
		LIMIT $4
	`, LeaderboardPath, dayStart, dayEnd, LeaderboardTopN)
	if err != nil {
		return fmt.Errorf("failed to query leaderboard data: %w", err)
	}
	defer rows.Close()

	// 收集结果
	type userCount struct {
		userID string
		count  int64
	}
	var results []userCount
	for rows.Next() {
		var uc userCount
		if err := rows.Scan(&uc.userID, &uc.count); err != nil {
			return fmt.Errorf("failed to scan row: %w", err)
		}
		results = append(results, uc)
	}

	if len(results) == 0 {
		log.Printf("[LEADERBOARD] No data for %s", dateStr)
		return nil
	}

	// 开始事务
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// UPSERT 每条记录
	datePrefix := now.Format("20060102")
	for rank, uc := range results {
		id := fmt.Sprintf("%s_%02d", datePrefix, rank+1)
		_, err := tx.Exec(`
			INSERT INTO leaderboard (id, date_str, rank, user_id, request_count, updated_at)
			VALUES ($1, $2, $3, $4, $5, NOW())
			ON CONFLICT (id) DO UPDATE SET
				user_id = EXCLUDED.user_id,
				request_count = EXCLUDED.request_count,
				updated_at = NOW()
		`, id, dateStr, rank+1, uc.userID, uc.count)
		if err != nil {
			return fmt.Errorf("failed to upsert leaderboard: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	log.Printf("[LEADERBOARD] Updated %d entries for %s", len(results), dateStr)
	return nil
}

// startLeaderboardScheduler 启动排行榜定时更新任务
func startLeaderboardScheduler(ctx context.Context) {
	ticker := time.NewTicker(LeaderboardUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[LEADERBOARD] Scheduler stopped")
			return
		case <-ticker.C:
			if err := updateLeaderboard(); err != nil {
				log.Printf("[LEADERBOARD] Update failed: %v", err)
			}
		}
	}
}

func main() {
	// 加载配置
	loadConfig()

	// 设置日志同时输出到控制台和文件
	logFile, err := os.OpenFile("gin.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic("无法创建日志文件: " + err.Error())
	}
	gin.DefaultWriter = io.MultiWriter(os.Stdout, logFile)
	gin.DefaultErrorWriter = io.MultiWriter(os.Stderr, logFile)
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	// 初始化数据库连接
	if err := initDB(); err != nil {
		log.Fatalf("无法连接数据库: %v", err)
	}
	defer db.Close()

	// 启动时执行一次 leaderboard 统计
	log.Println("[LEADERBOARD] Running initial statistics...")
	if err := updateLeaderboard(); err != nil {
		log.Printf("[LEADERBOARD] Initial update failed: %v", err)
	}

	// 启动 leaderboard 定时任务
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go startLeaderboardScheduler(ctx)

	r := gin.Default()

	r.Use(authMiddleware())

	for _, path := range allowedPaths {
		r.POST(path, proxyHandler)
	}

	// 注册 SSE 流式路由
	for _, path := range ssePaths {
		r.POST(path, sseProxyHandler)
	}

	// 处理 404 路由不匹配
	// 注意：authMiddleware 已经为认证成功的请求创建了 pending 日志，这里只需更新状态
	r.NoRoute(func(c *gin.Context) {
		// 如果 authMiddleware 已经创建了日志记录，更新其状态为 404
		completeRequestLogAsync(getRequestLogEntry(c, http.StatusNotFound))
		c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
	})

	r.Run(serverAddr)
}
