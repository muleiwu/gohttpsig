package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/muleiwu/gohttpsig"
)

func main() {
	// Create credentials from environment variables or use example values
	accessKeyID := os.Getenv("ACCESS_KEY_ID")
	secretAccessKey := os.Getenv("SECRET_ACCESS_KEY")

	if accessKeyID == "" || secretAccessKey == "" {
		log.Println("Using example credentials. Set ACCESS_KEY_ID and SECRET_ACCESS_KEY environment variables for real usage.")
		accessKeyID = "AKIAIOSFODNN7EXAMPLE"
		secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	}

	creds := &gohttpsig.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}

	// Create a credentials provider
	provider := gohttpsig.NewStaticCredentialsProvider(creds)

	// Create a signer
	signer := gohttpsig.NewSigner(provider)

	// Create an HTTP request
	url := "http://localhost:8080/api/data"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Sign the request
	service := "myservice"
	region := "us-east-1"

	signedReq, err := signer.Sign(context.Background(), req, service, region)
	if err != nil {
		log.Fatalf("Failed to sign request: %v", err)
	}

	fmt.Println("Request signed successfully!")
	fmt.Printf("Authorization: %s\n", signedReq.Request.Header.Get("Authorization"))
	fmt.Printf("X-Amz-Date: %s\n", signedReq.Request.Header.Get("X-Amz-Date"))
	fmt.Printf("X-Amz-Content-Sha256: %s\n", signedReq.Request.Header.Get("X-Amz-Content-Sha256"))
	fmt.Println()

	// Send the signed request
	fmt.Printf("Sending request to %s...\n", url)
	client := &http.Client{}
	resp, err := client.Do(signedReq.Request)
	if err != nil {
		log.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read and print response
	fmt.Printf("Response Status: %s\n", resp.Status)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}

	fmt.Printf("Response Body: %s\n", string(body))
}
