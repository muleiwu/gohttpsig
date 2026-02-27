package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/muleiwu/gohttpsig"
)

// AuthMiddleware creates a middleware that verifies request signatures
func AuthMiddleware(verifier *gohttpsig.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify the request signature
			result, err := verifier.Verify(context.Background(), r)
			if err != nil {
				log.Printf("Verification error: %v", err)
				http.Error(w, "Unauthorized: Invalid signature", http.StatusUnauthorized)
				return
			}

			if !result.Valid {
				log.Printf("Verification failed: %v", result.Error)
				http.Error(w, "Unauthorized: Invalid signature", http.StatusUnauthorized)
				return
			}

			// Log successful authentication
			log.Printf("Authenticated request from access key: %s (service: %s, region: %s)",
				result.AccessKeyID, result.Service, result.Region)

			// Add authentication info to request context if needed
			// ctx := context.WithValue(r.Context(), "accessKeyID", result.AccessKeyID)
			// r = r.WithContext(ctx)

			// Call next handler
			next.ServeHTTP(w, r)
		})
	}
}

func main() {
	// Create an in-memory credential store
	store := gohttpsig.NewInMemoryCredentialStore()

	// Add example credentials
	exampleCreds := &gohttpsig.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	if err := store.AddCredentials(exampleCreds); err != nil {
		log.Fatalf("Failed to add credentials: %v", err)
	}

	// In a real application, you would load credentials from a database or configuration
	// store := &DatabaseCredentialStore{db: db}

	// Create a verifier
	verifier := gohttpsig.NewVerifier(store)

	// Create the auth middleware
	authMiddleware := AuthMiddleware(verifier)

	// Create HTTP handlers
	mux := http.NewServeMux()

	// Protected endpoint - requires valid signature
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"message": "Hello! This is a protected resource.", "path": "%s"}`, r.URL.Path)
	})
	mux.Handle("/api/data", authMiddleware(protectedHandler))

	// Another protected endpoint
	userHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user": "authenticated-user", "endpoint": "user-info"}`)
	})
	mux.Handle("/api/user", authMiddleware(userHandler))

	// Public endpoint - no authentication required
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status": "healthy"}`)
	})

	// Start server
	addr := ":8080"
	log.Printf("Starting server on %s", addr)
	log.Println("Protected endpoints:")
	log.Println("  - http://localhost:8080/api/data")
	log.Println("  - http://localhost:8080/api/user")
	log.Println("Public endpoint:")
	log.Println("  - http://localhost:8080/health")
	log.Println()
	log.Println("Use the client example to send authenticated requests")

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
