package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	AUGMENT_API_URL   = "https://d12.api.augmentcode.com"
	AUGMENT_API_TOKEN = "5dc64c7be96ee4f40aafeb0882b9c48b1e55686c851308619f4100bb4ac88e81"
	AUTH_TOKEN        = "c98d048baeb2a02e50b1b2ba4e0a7374"
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
}

// ChatStreamRequest 用于验证 /chat-stream 请求
type ChatStreamRequest struct {
	Model               string        `json:"model"`
	Path                *string       `json:"path"`
	Prefix              *string       `json:"prefix"`
	SelectedCode        *string       `json:"selected_code"`
	Suffix              *string       `json:"suffix"`
	Message             string        `json:"message"`
	ChatHistory         []interface{} `json:"chat_history"`
	Lang                *string       `json:"lang"`
	UserGuidelines      string        `json:"user_guidelines"`
	WorkspaceGuidelines string        `json:"workspace_guidelines"`
	ThirdPartyOverride  *string       `json:"third_party_override"`
	ToolDefinitions     []interface{} `json:"tool_definitions"`
	Nodes               []interface{} `json:"nodes"`
	Mode                string        `json:"mode"`
	AgentMemories       string        `json:"agent_memories"`
	PersonaType         *string       `json:"persona_type"`
	SystemPrompt        *string       `json:"system_prompt"`
	Rules               []interface{} `json:"rules"`
}

const PROMPT_ENHANCER_MESSAGE_PREFIX = "⚠️ NO TOOLS ALLOWED ⚠️\n\nHere is an instruction that I'd like to give you, but it needs to be improved. Rewrite and enhance this instruction to make it clearer, more specific, less ambiguous, and correct any mistakes. Do not use any tools: reply immediately with your answer, even if you're not sure. Consider the context of our conversation history when enhancing the prompt. If there is code in triple backticks (```) consider whether it is a code sample and should remain unchanged.Reply with the following format:\n\n### BEGIN RESPONSE ###\nHere is an enhanced version of the original instruction that is more specific and clear:\n<augment-enhanced-prompt>enhanced prompt goes here</augment-enhanced-prompt>\n\n### END RESPONSE ###\n\nHere is my original instruction:\n\n"

// 请求头过滤：Host、Authorization 以及 nginx 反代带来的头
var skipRequestHeaders = map[string]bool{
	"Host":              true,
	"Authorization":     true,
	"X-Forwarded-For":   true,
	"X-Forwarded-Proto": true,
	"X-Forwarded-Host":  true,
	"X-Forwarded-Port":  true,
	"X-Real-Ip":         true,
	"X-Original-Uri":    true,
	"Via":               true,
	"Connection":        true,
}

// 响应头过滤：hop-by-hop 头，代理不应转发
var skipResponseHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Transfer-Encoding":   true,
	"Te":                  true,
	"Trailer":             true,
	"Upgrade":             true,
	"Proxy-Authorization": true,
	"Proxy-Authenticate":  true,
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

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token != AUTH_TOKEN {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Next()
	}
}

func validateChatStreamRequest(body []byte) error {
	var req ChatStreamRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return fmt.Errorf("invalid JSON")
	}

	// 检查必须为空字符串的字段
	if req.Model != "" {
		return fmt.Errorf("model must be empty")
	}
	if req.AgentMemories != "" {
		return fmt.Errorf("agent_memories must be empty")
	}
	if req.UserGuidelines != "" {
		return fmt.Errorf("user_guidelines must be empty")
	}
	if req.WorkspaceGuidelines != "" {
		return fmt.Errorf("workspace_guidelines must be empty")
	}

	// 检查必须为 null 的字段
	if req.Path != nil {
		return fmt.Errorf("path must be null")
	}
	if req.Prefix != nil {
		return fmt.Errorf("prefix must be null")
	}
	if req.SelectedCode != nil {
		return fmt.Errorf("selected_code must be null")
	}
	if req.Suffix != nil {
		return fmt.Errorf("suffix must be null")
	}
	if req.Lang != nil {
		return fmt.Errorf("lang must be null")
	}
	if req.PersonaType != nil {
		return fmt.Errorf("persona_type must be null")
	}
	if req.SystemPrompt != nil {
		return fmt.Errorf("system_prompt must be null")
	}
	if req.ThirdPartyOverride != nil {
		return fmt.Errorf("third_party_override must be null")
	}

	// 检查 mode 必须为 CHAT
	if req.Mode != "CHAT" {
		return fmt.Errorf("mode must be CHAT")
	}

	// 检查必须为空数组的字段
	if len(req.ToolDefinitions) > 0 {
		return fmt.Errorf("tool_definitions must be empty")
	}
	if len(req.Nodes) > 0 {
		return fmt.Errorf("nodes must be empty")
	}
	if len(req.Rules) > 0 {
		return fmt.Errorf("rules must be empty")
	}
	if len(req.ChatHistory) > 0 {
		return fmt.Errorf("chat_history must be empty")
	}

	// 检查 message 必须以固定 prompt 开头
	if !strings.HasPrefix(req.Message, PROMPT_ENHANCER_MESSAGE_PREFIX) {
		return fmt.Errorf("message must start with required prompt")
	}

	return nil
}

func proxyHandler(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	targetURL := AUGMENT_API_URL + c.Request.URL.Path

	req, err := http.NewRequestWithContext(c.Request.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	req.Header.Set("Authorization", "Bearer "+AUGMENT_API_TOKEN)

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
			log.Printf("[INFO] Client disconnected, upstream canceled: path=%s", c.Request.URL.Path)
			return
		}
		log.Printf("[502 ERROR] path=%s, error=%v, headers=%v, body=%s", c.Request.URL.Path, err, c.Request.Header, string(body))
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "failed to forward request"})
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
		return
	}

	if resp.StatusCode >= 400 {
		log.Printf("[%d FROM UPSTREAM] path=%s, headers=%v, reqBody=%s, respBody=%s", resp.StatusCode, c.Request.URL.Path, c.Request.Header, string(body), string(respBody))
	}

	c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
}

func sseProxyHandler(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	// 验证 /chat-stream 请求内容
	if c.FullPath() == "/chat-stream" {
		if err := validateChatStreamRequest(body); err != nil {
			log.Printf("[403 FORBIDDEN] path=%s, reason=%s, body=%s", c.Request.URL.Path, err.Error(), string(body))
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "request validation failed"})
			return
		}
	}

	targetURL := AUGMENT_API_URL + c.Request.URL.Path

	req, err := http.NewRequestWithContext(c.Request.Context(), "POST", targetURL, bytes.NewReader(body))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	req.Header.Set("Authorization", "Bearer "+AUGMENT_API_TOKEN)

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
			log.Printf("[INFO] Client disconnected, upstream canceled: path=%s", c.Request.URL.Path)
			return
		}
		log.Printf("[502 ERROR] path=%s, error=%v, headers=%v, body=%s", c.Request.URL.Path, err, c.Request.Header, string(body))
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "failed to forward request: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	// 上游返回错误状态码时，直接转发错误响应（非流式）
	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[%d FROM UPSTREAM] path=%s, headers=%v, reqBody=%s, respBody=%s", resp.StatusCode, c.Request.URL.Path, c.Request.Header, string(body), string(respBody))
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), respBody)
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
		return
	}

	// 流式读取并转发
	reader := bufio.NewReader(resp.Body)
	for {
		select {
		case <-c.Request.Context().Done():
			return
		default:
			line, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}

			_, writeErr := c.Writer.Write(line)
			if writeErr != nil {
				return
			}

			flusher.Flush()
		}
	}
}

func main() {
	// 设置日志同时输出到控制台和文件
	logFile, err := os.OpenFile("gin.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		panic("无法创建日志文件: " + err.Error())
	}
	gin.DefaultWriter = io.MultiWriter(os.Stdout, logFile)
	gin.DefaultErrorWriter = io.MultiWriter(os.Stderr, logFile)
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

	r := gin.Default()

	r.Use(authMiddleware())

	for _, path := range allowedPaths {
		r.POST(path, proxyHandler)
	}

	// 注册 SSE 流式路由
	for _, path := range ssePaths {
		r.POST(path, sseProxyHandler)
	}

	r.Run("127.0.0.1:3009")
}
