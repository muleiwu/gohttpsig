package gohttpsig

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

const (
	// AccessKeyID 长度（AWS 标准）
	AccessKeyIDLength = 20

	// SecretAccessKey 长度（AWS 标准）
	SecretAccessKeyLength = 40

	// AccessKeyID 字符集：大写字母和数字
	// 使用所有大写字母和数字以兼容 AWS 格式
	accessKeyCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// SecretAccessKey 字符集：Base64 URL安全字符集
	secretKeyCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// CredentialPrefix 定义不同类型凭证的前缀
type CredentialPrefix string

const (
	// PrefixPermanent 永久凭证前缀（类似 AWS AKIA）
	PrefixPermanent CredentialPrefix = "AKIA"

	// PrefixTemporary 临时凭证前缀（类似 AWS ASIA）
	PrefixTemporary CredentialPrefix = "ASIA"

	// PrefixService 服务凭证前缀
	PrefixService CredentialPrefix = "AKSA"
)

// GenerateCredentials 生成一对新的访问凭证
// 返回 AccessKeyID 和 SecretAccessKey
func GenerateCredentials() (*Credentials, error) {
	return GenerateCredentialsWithPrefix(PrefixPermanent)
}

// GenerateCredentialsWithPrefix 生成带指定前缀的访问凭证
func GenerateCredentialsWithPrefix(prefix CredentialPrefix) (*Credentials, error) {
	accessKeyID, err := GenerateAccessKeyID(prefix)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access key ID: %w", err)
	}

	secretAccessKey, err := GenerateSecretAccessKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate secret access key: %w", err)
	}

	return &Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}, nil
}

// GenerateAccessKeyID 生成一个加密安全的 AccessKeyID
// 格式：PREFIX + 16个随机字符 = 20个字符
func GenerateAccessKeyID(prefix CredentialPrefix) (string, error) {
	// 验证前缀长度
	if len(prefix) != 4 {
		return "", fmt.Errorf("prefix must be exactly 4 characters, got %d", len(prefix))
	}

	// 生成随机部分（20 - 4 = 16个字符）
	randomLength := AccessKeyIDLength - len(prefix)
	randomPart, err := generateRandomString(randomLength, accessKeyCharset)
	if err != nil {
		return "", err
	}

	return string(prefix) + randomPart, nil
}

// GenerateSecretAccessKey 生成一个加密安全的 SecretAccessKey
// 使用 crypto/rand 生成高熵随机字节，然后编码为 Base64
func GenerateSecretAccessKey() (string, error) {
	return GenerateSecretAccessKeyWithLength(SecretAccessKeyLength)
}

// GenerateSecretAccessKeyWithLength 生成指定长度的 SecretAccessKey
func GenerateSecretAccessKeyWithLength(length int) (string, error) {
	if length < 32 {
		return "", fmt.Errorf("secret key length must be at least 32 characters, got %d", length)
	}

	// 方案1：使用 Base64 编码（AWS 风格）
	// 需要 length * 3 / 4 个随机字节来生成 length 个 Base64 字符
	numBytes := (length * 3) / 4
	randomBytes := make([]byte, numBytes)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Base64 编码
	encoded := base64.StdEncoding.EncodeToString(randomBytes)

	// 截取到指定长度
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}

// GenerateSecretAccessKeyCustom 使用自定义字符集生成 SecretAccessKey
// 这种方式提供更均匀的字符分布
func GenerateSecretAccessKeyCustom() (string, error) {
	return generateRandomString(SecretAccessKeyLength, secretKeyCharset)
}

// generateRandomString 使用加密安全的随机数生成器生成随机字符串
func generateRandomString(length int, charset string) (string, error) {
	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))

	for i := 0; i < length; i++ {
		// 使用 crypto/rand 生成随机索引
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}

		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}

// GenerateSessionToken 生成会话令牌（用于临时凭证）
func GenerateSessionToken() (string, error) {
	// 会话令牌通常更长，包含更多信息
	// AWS 会话令牌可达数百字符
	tokenLength := 64

	randomBytes := make([]byte, tokenLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}

	// 使用 Base64 URL 安全编码
	token := base64.URLEncoding.EncodeToString(randomBytes)

	// 移除填充（=）使其更简洁
	token = strings.TrimRight(token, "=")

	return token, nil
}

// ValidateAccessKeyID 验证 AccessKeyID 格式
func ValidateAccessKeyID(accessKeyID string) error {
	if len(accessKeyID) != AccessKeyIDLength {
		return fmt.Errorf("access key ID must be %d characters, got %d", AccessKeyIDLength, len(accessKeyID))
	}

	// 检查前缀
	prefix := accessKeyID[:4]
	validPrefixes := []string{
		string(PrefixPermanent),
		string(PrefixTemporary),
		string(PrefixService),
	}

	validPrefix := false
	for _, p := range validPrefixes {
		if prefix == p {
			validPrefix = true
			break
		}
	}

	if !validPrefix {
		return fmt.Errorf("invalid access key ID prefix: %s", prefix)
	}

	// 检查字符集（所有字符应该是大写字母或数字）
	for i := 0; i < len(accessKeyID); i++ {
		c := accessKeyID[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid character in access key ID: %c", c)
		}
	}

	return nil
}

// ValidateSecretAccessKey 验证 SecretAccessKey 强度
func ValidateSecretAccessKey(secretKey string) error {
	if len(secretKey) < 32 {
		return fmt.Errorf("secret key must be at least 32 characters, got %d", len(secretKey))
	}

	// 检查是否包含足够的字符类型
	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, c := range secretKey {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case strings.ContainsRune("+/=", c):
			hasSpecial = true
		}
	}

	// 至少需要3种类型的字符
	charTypes := 0
	if hasUpper {
		charTypes++
	}
	if hasLower {
		charTypes++
	}
	if hasDigit {
		charTypes++
	}
	if hasSpecial {
		charTypes++
	}

	if charTypes < 3 {
		return fmt.Errorf("secret key must contain at least 3 different character types (upper, lower, digit, special)")
	}

	return nil
}

// CredentialStrength 评估凭证强度
type CredentialStrength struct {
	IsStrong bool
	Score    int // 0-100
	Issues   []string
}

// EvaluateCredentialStrength 评估凭证的安全强度
func EvaluateCredentialStrength(creds *Credentials) *CredentialStrength {
	strength := &CredentialStrength{
		Score:  100,
		Issues: []string{},
	}

	// 检查 AccessKeyID
	if err := ValidateAccessKeyID(creds.AccessKeyID); err != nil {
		strength.Score -= 30
		strength.Issues = append(strength.Issues, fmt.Sprintf("AccessKeyID: %v", err))
	}

	// 检查 SecretAccessKey 长度
	if len(creds.SecretAccessKey) < 32 {
		strength.Score -= 30
		strength.Issues = append(strength.Issues, "SecretAccessKey too short (minimum 32 characters)")
	} else if len(creds.SecretAccessKey) < 40 {
		strength.Score -= 10
		strength.Issues = append(strength.Issues, "SecretAccessKey shorter than recommended (40 characters)")
	}

	// 检查字符多样性
	if err := ValidateSecretAccessKey(creds.SecretAccessKey); err != nil {
		strength.Score -= 20
		strength.Issues = append(strength.Issues, fmt.Sprintf("SecretAccessKey: %v", err))
	}

	strength.IsStrong = strength.Score >= 80

	return strength
}
