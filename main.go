package main

import (
	"bytes"
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

var httpClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
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

func uaMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ua := c.GetHeader("User-Agent")
		if !strings.HasPrefix(ua, "augment.cli/") || !strings.HasSuffix(ua, "/mcp") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid user agent"})
			return
		}

		c.Next()
	}
}

func proxyHandler(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	targetURL := AUGMENT_API_URL + c.Request.URL.Path

	req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	req.Header.Set("Authorization", "Bearer "+AUGMENT_API_TOKEN)

	// 需要排除的头：Host、Authorization 以及nginx反代带来的头
	skipHeaders := map[string]bool{
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

	for key, values := range c.Request.Header {
		if skipHeaders[key] {
			continue
		}
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[502 ERROR] path=%s, error=%v, headers=%v, body=%s", c.Request.URL.Path, err, c.Request.Header, string(body))
		c.AbortWithStatusJSON(http.StatusBadGateway, gin.H{"error": "failed to forward request"})
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
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
	// r.Use(uaMiddleware())

	for _, path := range allowedPaths {
		r.POST(path, proxyHandler)
	}

	r.Run("127.0.0.1:3009")
}
