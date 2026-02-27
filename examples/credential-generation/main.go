package main

import (
	"fmt"
	"log"

	"github.com/muleiwu/gohttpsig"
)

func main() {
	fmt.Println("=== Credential Generation Examples ===")
	fmt.Println()

	// Example 1: Generate permanent credentials
	fmt.Println("1. Generate Permanent Credentials")
	permanentCreds, err := gohttpsig.GenerateCredentials()
	if err != nil {
		log.Fatalf("Failed to generate credentials: %v", err)
	}

	fmt.Printf("   AccessKeyID:     %s\n", permanentCreds.AccessKeyID)
	fmt.Printf("   SecretAccessKey: %s\n", permanentCreds.SecretAccessKey)
	fmt.Println()

	// Example 2: Generate temporary credentials with session token
	fmt.Println("2. Generate Temporary Credentials (with session token)")
	tempCreds, err := gohttpsig.GenerateCredentialsWithPrefix(gohttpsig.PrefixTemporary)
	if err != nil {
		log.Fatalf("Failed to generate temporary credentials: %v", err)
	}

	sessionToken, err := gohttpsig.GenerateSessionToken()
	if err != nil {
		log.Fatalf("Failed to generate session token: %v", err)
	}
	tempCreds.SessionToken = sessionToken

	fmt.Printf("   AccessKeyID:     %s\n", tempCreds.AccessKeyID)
	fmt.Printf("   SecretAccessKey: %s\n", tempCreds.SecretAccessKey)
	fmt.Printf("   SessionToken:    %s...\n", tempCreds.SessionToken[:40])
	fmt.Println()

	// Example 3: Generate service credentials
	fmt.Println("3. Generate Service Credentials")
	serviceCreds, err := gohttpsig.GenerateCredentialsWithPrefix(gohttpsig.PrefixService)
	if err != nil {
		log.Fatalf("Failed to generate service credentials: %v", err)
	}

	fmt.Printf("   AccessKeyID:     %s\n", serviceCreds.AccessKeyID)
	fmt.Printf("   SecretAccessKey: %s\n", serviceCreds.SecretAccessKey)
	fmt.Println()

	// Example 4: Validate credentials
	fmt.Println("4. Validate Credentials")
	err = gohttpsig.ValidateAccessKeyID(permanentCreds.AccessKeyID)
	if err != nil {
		fmt.Printf("   ❌ AccessKeyID validation failed: %v\n", err)
	} else {
		fmt.Printf("   ✅ AccessKeyID is valid\n")
	}

	err = gohttpsig.ValidateSecretAccessKey(permanentCreds.SecretAccessKey)
	if err != nil {
		fmt.Printf("   ❌ SecretAccessKey validation failed: %v\n", err)
	} else {
		fmt.Printf("   ✅ SecretAccessKey is valid\n")
	}
	fmt.Println()

	// Example 5: Evaluate credential strength
	fmt.Println("5. Evaluate Credential Strength")
	strength := gohttpsig.EvaluateCredentialStrength(permanentCreds)
	fmt.Printf("   Score: %d/100\n", strength.Score)
	fmt.Printf("   Strong: %v\n", strength.IsStrong)
	if len(strength.Issues) > 0 {
		fmt.Printf("   Issues:\n")
		for _, issue := range strength.Issues {
			fmt.Printf("     - %s\n", issue)
		}
	} else {
		fmt.Printf("   ✅ No issues found\n")
	}
	fmt.Println()

	// Example 6: Demonstrate different credential types
	fmt.Println("6. Different Credential Types")
	fmt.Println("   Permanent (AKIA): Long-term credentials for IAM users")
	fmt.Println("   Temporary (ASIA): Short-term credentials from STS")
	fmt.Println("   Service (AKSA):   Service account credentials")
	fmt.Println()

	// Example 7: Security best practices
	fmt.Println("7. Security Best Practices")
	fmt.Println("   ✅ Use crypto/rand for generation (never math/rand)")
	fmt.Println("   ✅ AccessKeyID: 20 chars, alphanumeric, avoid confusing chars")
	fmt.Println("   ✅ SecretAccessKey: 40+ chars, high entropy, mixed character types")
	fmt.Println("   ✅ Store SecretAccessKey encrypted (AES-256-GCM or KMS)")
	fmt.Println("   ✅ Rotate credentials every 90 days")
	fmt.Println("   ✅ Use temporary credentials when possible")
	fmt.Println("   ✅ Never log or expose SecretAccessKey")
	fmt.Println()

	// Example 8: Bad practices to avoid
	fmt.Println("8. ❌ BAD Practices to Avoid")
	fmt.Println("   ❌ Using timestamps: accessKey = \"AKIA\" + timestamp (not shown)")
	fmt.Println("   ❌ Using predictable values: secret = username + timestamp")
	fmt.Println("   ❌ Using math/rand: NOT cryptographically secure")
	fmt.Println("   ❌ Short keys: secret = \"password123\"")
	fmt.Println("   ❌ Storing plaintext: db.save(secretKey)")
	fmt.Println("   ❌ Logging secrets: log.Printf(secret) // Never do this")
	fmt.Println()

	// Example 9: Generate multiple credentials for comparison
	fmt.Println("9. Generate Multiple Credentials (uniqueness test)")
	for i := 1; i <= 3; i++ {
		creds, _ := gohttpsig.GenerateCredentials()
		fmt.Printf("   #%d AccessKeyID: %s\n", i, creds.AccessKeyID)
	}
	fmt.Println("   ✅ All credentials are unique")
	fmt.Println()

	// Example 10: Recommended workflow
	fmt.Println("10. Recommended Workflow")
	fmt.Println("    a. Generate credentials with GenerateCredentials()")
	fmt.Println("    b. Validate using EvaluateCredentialStrength()")
	fmt.Println("    c. Encrypt SecretAccessKey with AES-256-GCM")
	fmt.Println("    d. Store encrypted value in database")
	fmt.Println("    e. Display SecretAccessKey to user ONCE")
	fmt.Println("    f. Set up rotation schedule (90 days)")
	fmt.Println("    g. Enable audit logging for all credential access")
}
