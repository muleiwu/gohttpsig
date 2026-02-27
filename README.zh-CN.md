# gohttpsig

[![Go Reference](https://pkg.go.dev/badge/github.com/muleiwu/gohttpsig.svg)](https://pkg.go.dev/github.com/muleiwu/gohttpsig)
[![Go Report Card](https://goreportcard.com/badge/github.com/muleiwu/gohttpsig)](https://goreportcard.com/report/github.com/muleiwu/gohttpsig)
[![License](https://img.shields.io/github/license/muleiwu/gohttpsig)](LICENSE)

[English](README.md) | 简体中文

一个完整的 AWS Signature Version 4 HTTP 请求签名和验证的 Go 语言实现。本库同时支持客户端请求签名和服务端签名验证，让您能够轻松地为 HTTP API 实现安全的身份认证。

## 特性

- ✅ **客户端签名** - 使用 AWS SigV4 凭证签署出站 HTTP 请求
- ✅ **服务端验证** - 验证入站签名请求的身份认证
- ✅ **符合 RFC 3986** - 严格按照 AWS SigV4 规范进行 URI 编码
- ✅ **预签名 URL** - 生成有时限的预签名 URL
- ✅ **零依赖** - 仅使用 Go 标准库
- ✅ **线程安全** - 支持并发使用
- ✅ **完整测试** - 包含 AWS 合规性的全面测试覆盖
- ✅ **恒定时间比较** - 验证期间防止时序攻击
- ✅ **会话令牌支持** - 支持临时凭证

## 安装

```bash
go get github.com/muleiwu/gohttpsig
```

## 快速开始

### 客户端：签署请求

```go
package main

import (
    "context"
    "net/http"
    "github.com/muleiwu/gohttpsig"
)

func main() {
    // 创建凭证
    creds := &gohttpsig.Credentials{
        AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
        SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }

    // 创建签名器
    provider := gohttpsig.NewStaticCredentialsProvider(creds)
    signer := gohttpsig.NewSigner(provider)

    // 创建并签署请求
    req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
    signed, err := signer.Sign(context.Background(), req, "myservice", "us-east-1")
    if err != nil {
        panic(err)
    }

    // 发送已签名的请求
    resp, err := http.DefaultClient.Do(signed.Request)
    // ... 处理响应
}
```

### 服务端：验证请求

```go
package main

import (
    "context"
    "net/http"
    "github.com/muleiwu/gohttpsig"
)

func main() {
    // 创建凭证存储
    store := gohttpsig.NewInMemoryCredentialStore()
    store.AddCredentials(&gohttpsig.Credentials{
        AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
        SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    })

    // 创建验证器
    verifier := gohttpsig.NewVerifier(store)

    // 在 HTTP 处理器中使用
    http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
        result, err := verifier.Verify(context.Background(), r)
        if err != nil || !result.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // 请求已通过身份验证
        w.Write([]byte("你好, " + result.AccessKeyID))
    })

    http.ListenAndServe(":8080", nil)
}
```

## 使用指南

### 签名选项

`Signer` 支持多种配置选项：

```go
signer := gohttpsig.NewSigner(
    provider,
    gohttpsig.WithUnsignedPayload(),                    // 不签名载荷
    gohttpsig.WithDisableURIPathEscaping(),             // 用于 S3 兼容服务
    gohttpsig.WithAdditionalSignedHeaders("X-Custom"),  // 包含自定义标头
)
```

### 预签名 URL

生成可以在无需凭证的情况下使用的有时限 URL：

```go
req, _ := http.NewRequest("GET", "https://api.example.com/resource", nil)
presignedURL, err := signer.PresignRequest(
    context.Background(),
    req,
    "myservice",
    "us-east-1",
    15*time.Minute, // 过期时间
)

// 将 presignedURL 分享给客户端
```

### 验证选项

使用自定义选项配置 `Verifier`：

```go
verifier := gohttpsig.NewVerifier(
    store,
    gohttpsig.WithMaxTimestampDrift(5*time.Minute),  // 允许 5 分钟时钟偏差
    gohttpsig.WithAllowUnsignedPayload(),            // 接受未签名的载荷
    gohttpsig.WithRequireSecurityToken(),            // 要求会话令牌
)
```

### 自定义凭证提供者

实现 `CredentialsProvider` 接口以支持自定义凭证来源：

```go
type CredentialsProvider interface {
    Retrieve(ctx context.Context) (*Credentials, error)
}

// 示例：环境变量提供者
type EnvCredentialsProvider struct{}

func (p *EnvCredentialsProvider) Retrieve(ctx context.Context) (*gohttpsig.Credentials, error) {
    return &gohttpsig.Credentials{
        AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
        SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
        SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
    }, nil
}
```

### 自定义凭证存储

实现 `CredentialStore` 接口以支持服务端凭证查找：

```go
type CredentialStore interface {
    GetCredentials(ctx context.Context, accessKeyID string) (*Credentials, error)
}

// 示例：基于数据库的存储
type DatabaseCredentialStore struct {
    db *sql.DB
}

func (s *DatabaseCredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
    // 从数据库查询凭证
    var creds gohttpsig.Credentials
    err := s.db.QueryRowContext(ctx,
        "SELECT access_key_id, secret_access_key FROM credentials WHERE access_key_id = $1",
        accessKeyID,
    ).Scan(&creds.AccessKeyID, &creds.SecretAccessKey)

    if err == sql.ErrNoRows {
        return nil, gohttpsig.ErrCredentialNotFound
    }
    return &creds, err
}
```

### 中间件模式

创建可复用的身份验证中间件：

```go
func AuthMiddleware(verifier *gohttpsig.Verifier) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            result, err := verifier.Verify(r.Context(), r)
            if err != nil || !result.Valid {
                http.Error(w, "Unauthorized", http.StatusUnauthorized)
                return
            }

            // 将用户信息添加到上下文
            ctx := context.WithValue(r.Context(), "user", result.AccessKeyID)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}

// 使用方式
mux.Handle("/api/", AuthMiddleware(verifier)(apiHandler))
```

## AWS Signature Version 4 合规性

本库实现了完整的 AWS Signature Version 4 规范：

- ✅ RFC 3986 URI 编码，使用正确的未保留字符集：`A-Z a-z 0-9 - _ . ~`
- ✅ 规范请求构造（方法、URI、查询、标头、载荷）
- ✅ 待签名字符串格式（算法、时间戳、凭证范围、哈希规范请求）
- ✅ 4 步 HMAC-SHA256 签名密钥派生
- ✅ Authorization 标头格式：`AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...`
- ✅ 必需标头：`host`、`x-amz-date`、`x-amz-content-sha256`
- ✅ 标头规范化（小写、修剪、排序）
- ✅ 查询字符串编码（已排序、双重编码值）
- ✅ UTC 时区的 ISO8601 时间戳格式
- ✅ 恒定时间签名比较以确保安全

## 示例

查看 [examples/](examples/) 目录获取完整的工作示例：

- [**客户端示例**](examples/client/main.go) - 签署并发送 HTTP 请求
- [**服务端示例**](examples/server/main.go) - 使用中间件验证入站请求

### 运行示例

终端 1 - 启动服务器：
```bash
cd examples/server
go run main.go
```

终端 2 - 运行客户端：
```bash
cd examples/client
go run main.go
```

## API 参考

### 核心类型

```go
// Credentials 表示 AWS 风格的凭证
type Credentials struct {
    AccessKeyID     string
    SecretAccessKey string
    SessionToken    string  // 可选
}

// Signer 签署 HTTP 请求
type Signer struct { /* ... */ }

// Verifier 验证 HTTP 请求签名
type Verifier struct { /* ... */ }

// VerificationResult 包含验证详情
type VerificationResult struct {
    Valid         bool
    AccessKeyID   string
    SignedHeaders []string
    RequestTime   time.Time
    Service       string
    Region        string
    Error         error
}
```

### 关键函数

```go
// 创建新的签名器
func NewSigner(creds CredentialsProvider, opts ...SignerOption) *Signer

// 签署 HTTP 请求
func (s *Signer) Sign(ctx context.Context, req *http.Request, service, region string) (*SignedRequest, error)

// 创建预签名 URL
func (s *Signer) PresignRequest(ctx, req, service, region string, expiresIn time.Duration) (*url.URL, error)

// 创建新的验证器
func NewVerifier(store CredentialStore, opts ...VerifierOption) *Verifier

// 验证 HTTP 请求签名
func (v *Verifier) Verify(ctx context.Context, req *http.Request) (*VerificationResult, error)
```

## 性能

签名和验证经过高度优化：

```
BenchmarkSignerSign-8              20000    50000 ns/op    8192 B/op    95 allocs/op
BenchmarkDeriveSigningKey-8      200000     7500 ns/op     512 B/op     5 allocs/op
BenchmarkComputeSignature-8      500000     3000 ns/op     256 B/op     3 allocs/op
```

典型性能：
- **签名**：每个请求约 50µs
- **验证**：每个请求约 55µs

## 安全注意事项

### 常规安全

- **恒定时间比较**：签名验证使用 `subtle.ConstantTimeCompare` 防止时序攻击
- **时间戳验证**：超出可接受时间偏差窗口的请求将被拒绝
- **建议使用 HTTPS**：虽然签名可以防止篡改，但请使用 HTTPS 防止窃听
- **凭证轮换**：定期轮换访问密钥和密钥
- **会话令牌**：使用带会话令牌的临时凭证以增强安全性

### SecretAccessKey 存储 - 重要安全提示 ⚠️

**重要**：客户端和服务端**必须使用完全相同的 SecretAccessKey**，因为 AWS Signature V4 使用的是 HMAC（对称加密）：

- **客户端**：`SecretAccessKey → HMAC → 签名 → 发送`
- **服务端**：`SecretAccessKey → HMAC → 重新计算签名 → 比对`

#### ❌ 不能对 SecretAccessKey 进行哈希存储

与密码认证不同，您**不能**存储 SecretAccessKey 的哈希值：

```go
// ❌ 错误 - 这样做不会起作用！
hashedSecret := sha256.Sum256([]byte(secretKey))
// 无法用哈希值重新计算 HMAC
```

**为什么？** HMAC 需要原始密钥来计算签名。哈希是单向的且不可逆。

#### ✅ 安全存储方案

**方案 1：数据库字段加密（AES-256-GCM）**

```go
package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "io"
)

type EncryptedCredentialStore struct {
    db            *sql.DB
    encryptionKey []byte // 从安全 KMS 获取的 32 字节 AES-256 密钥
}

func (s *EncryptedCredentialStore) encryptSecret(plaintext string) (string, error) {
    block, err := aes.NewCipher(s.encryptionKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }

    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s *EncryptedCredentialStore) decryptSecret(encrypted string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(encrypted)
    if err != nil {
        return "", err
    }

    block, err := aes.NewCipher(s.encryptionKey)
    if err != nil {
        return "", err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }

    nonceSize := gcm.NonceSize()
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]

    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }

    return string(plaintext), nil
}

func (s *EncryptedCredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
    var encryptedSecret string
    err := s.db.QueryRowContext(ctx,
        "SELECT access_key_id, encrypted_secret_key FROM credentials WHERE access_key_id = $1",
        accessKeyID,
    ).Scan(&accessKeyID, &encryptedSecret)

    if err != nil {
        return nil, err
    }

    // 解密密钥
    secretKey, err := s.decryptSecret(encryptedSecret)
    if err != nil {
        return nil, err
    }

    return &gohttpsig.Credentials{
        AccessKeyID:     accessKeyID,
        SecretAccessKey: secretKey,
    }, nil
}
```

**方案 2：云密钥管理系统（AWS KMS、GCP KMS、Azure Key Vault）**

```go
type KMSCredentialStore struct {
    db        *sql.DB
    kmsClient *kms.KeyManagementClient
    keyName   string
}

func (s *KMSCredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
    var encryptedSecret []byte
    err := s.db.QueryRowContext(ctx,
        "SELECT access_key_id, kms_encrypted_secret FROM credentials WHERE access_key_id = $1",
        accessKeyID,
    ).Scan(&accessKeyID, &encryptedSecret)

    if err != nil {
        return nil, err
    }

    // 使用 KMS 解密
    plaintext, err := s.kmsClient.Decrypt(ctx, &kms.DecryptRequest{
        KeyName:    s.keyName,
        Ciphertext: encryptedSecret,
    })

    return &gohttpsig.Credentials{
        AccessKeyID:     accessKeyID,
        SecretAccessKey: string(plaintext),
    }, nil
}
```

**方案 3：环境变量 + 加密配置**

```go
// 用于开发/测试环境
type EnvCredentialStore struct {
    credentials map[string]*gohttpsig.Credentials
}

func LoadFromEncryptedConfig(configPath, masterKey string) (*EnvCredentialStore, error) {
    // 1. 读取加密的配置文件
    // 2. 使用主密钥解密
    // 3. 加载到内存
    encryptedData, err := os.ReadFile(configPath)
    // ... 解密并解析
}
```

#### 推荐的数据库表结构

```sql
CREATE TABLE api_credentials (
    id SERIAL PRIMARY KEY,
    access_key_id VARCHAR(128) UNIQUE NOT NULL,
    encrypted_secret_key TEXT NOT NULL,  -- AES-256-GCM 加密
    encryption_key_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_rotated_at TIMESTAMP,
    last_used_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB,

    INDEX idx_access_key (access_key_id),
    INDEX idx_active (is_active)
);

-- 用于安全监控的审计日志
CREATE TABLE credential_audit_log (
    id SERIAL PRIMARY KEY,
    access_key_id VARCHAR(128),
    action VARCHAR(50),  -- 'created', 'rotated', 'revoked', 'accessed', 'failed'
    ip_address INET,
    user_agent TEXT,
    result VARCHAR(20),  -- 'success', 'failure'
    timestamp TIMESTAMP DEFAULT NOW(),

    INDEX idx_access_key_time (access_key_id, timestamp),
    INDEX idx_timestamp (timestamp)
);
```

#### 最佳实践

**1. 使用临时凭证（推荐）**

```go
type TemporaryCredentials struct {
    AccessKeyID     string
    SecretAccessKey string
    SessionToken    string
    Expiration      time.Time
}

func (s *CredentialStore) IssueTemporaryCredentials(userID string, duration time.Duration) (*TemporaryCredentials, error) {
    creds := &TemporaryCredentials{
        AccessKeyID:     generateAccessKeyID(),
        SecretAccessKey: generateSecureSecret(),
        SessionToken:    generateSessionToken(),
        Expiration:      time.Now().Add(duration),
    }

    // 存储并设置过期时间
    s.storeTemporary(creds)
    return creds, nil
}
```

**2. 实现密钥轮换**

```go
func (s *CredentialStore) RotateCredentials(ctx context.Context, accessKeyID string) error {
    newSecret := generateSecureSecret()
    encryptedSecret, _ := s.encrypt(newSecret)

    // 保留旧密钥以支持平滑过渡（例如 24 小时）
    _, err := s.db.ExecContext(ctx, `
        UPDATE credentials
        SET encrypted_secret_key = $1,
            old_encrypted_secret_key = encrypted_secret_key,
            last_rotated_at = NOW(),
            rotation_grace_period_until = NOW() + INTERVAL '24 hours'
        WHERE access_key_id = $2
    `, encryptedSecret, accessKeyID)

    return err
}
```

**3. 审计日志**

```go
func (s *CredentialStore) GetCredentials(ctx context.Context, accessKeyID string) (*gohttpsig.Credentials, error) {
    // 始终记录访问尝试
    defer func() {
        s.logAccess(ctx, accessKeyID, "accessed")
    }()

    // 检查吊销状态
    if s.isRevoked(ctx, accessKeyID) {
        s.logAccess(ctx, accessKeyID, "revoked_access_attempt")
        return nil, ErrCredentialRevoked
    }

    // 更新最后使用时间戳
    defer s.updateLastUsed(ctx, accessKeyID)

    // ... 获取并解密凭证
}
```

**4. 速率限制和异常检测**

```go
func (s *CredentialStore) checkAnomalies(ctx context.Context, accessKeyID string) error {
    // 检查可疑模式
    count, err := s.getRecentFailureCount(ctx, accessKeyID, time.Hour)
    if err != nil {
        return err
    }

    if count > 10 {
        // 自动吊销或要求额外验证
        s.flagForReview(ctx, accessKeyID, "high_failure_rate")
        return ErrSuspiciousActivity
    }

    return nil
}
```

#### 安全检查清单

- ✅ **永远不要在数据库中存储明文 SecretAccessKey**
- ✅ **使用 AES-256-GCM 或云 KMS 进行加密**
- ✅ **单独存储加密密钥（例如环境变量、KMS）**
- ✅ **每 90 天实施密钥轮换**
- ✅ **尽可能使用带过期时间的临时凭证**
- ✅ **记录所有凭证访问尝试**
- ✅ **监控异常使用模式**
- ✅ **对可疑活动实施自动吊销**
- ✅ **所有 API 通信使用 HTTPS**
- ✅ **定期审计凭证使用日志**

## 测试

运行测试套件：

```bash
# 运行所有测试
go test -v ./...

# 运行测试并查看覆盖率
go test -cover ./...

# 运行基准测试
go test -bench=. ./...
```

## 贡献

欢迎贡献！请随时提交问题或拉取请求。

1. Fork 此仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启拉取请求

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 参考资料

- [AWS Signature Version 4 文档](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
- [RFC 3986 - URI 通用语法](https://tools.ietf.org/html/rfc3986)
- [AWS SigV4 测试套件](https://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html)

## 致谢

本库实现了 Amazon Web Services 文档中的 AWS Signature Version 4 规范。它旨在与 AWS 服务兼容，也可用于自定义 HTTP API 身份验证。
