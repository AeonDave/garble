package main

import "fmt"

const (
	secretKey   = "my-secret-api-key-123456"
	password    = "SuperSecretP@ssw0rd!"
	apiEndpoint = "https://api.example.com/v1/secure"
)

var (
	token       = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	credentials = []byte("admin:password:token")
)

func main() {
	fmt.Println("=== Improved Simple XOR Obfuscation Test ===")
	fmt.Println()
	fmt.Println("Secret Key:", secretKey)
	fmt.Println("Password:", password)
	fmt.Println("API Endpoint:", apiEndpoint)
	fmt.Println("Token:", token)
	fmt.Println("Credentials:", string(credentials))
	message := "Hello, " + "World" + "!"
	fmt.Println("Message:", message)
	data := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}
	fmt.Println("Byte data:", string(data))
	special := "Test\n\tSpecialChars"
	fmt.Println("Special:", special)
	repeated := "aaaaaaaaaaaaaaaaaa"
	fmt.Println("Repeated:", repeated)
	empty := ""
	single := "x"
	fmt.Println("Empty:", empty, "Single:", single)
	large := `This is a much longer literal that contains multiple sentences.
It spans multiple lines and includes various characters like numbers 123456,
special symbols !@#$%^&*(), and even some unicode: ✓ ✗ ★ ♥
The improved XOR obfuscator should handle this with nonce, position-dependent
mixing, and chained operations for better security while maintaining performance.`
	fmt.Println("Large literal length:", len(large))
	fmt.Println()
	fmt.Println("✅ All literals processed successfully with improved XOR!")
	fmt.Println("Features: Nonce + Position-mixing + Chaining + External keys")
}
