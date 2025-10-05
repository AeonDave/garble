package main

import "fmt"

const (
	secretMessage = "This is a secret message that should be obfuscated with ASCON-128!"
	apiKey        = "my-super-secret-api-key-12345"
	password      = "P@ssw0rd!2024"
)

var (
	databaseURL = "postgresql://user:pass@localhost:5432/mydb"
	credentials = []byte("username:password:token")
)

func main() {
	fmt.Println("=== ASCON-128 Literal Obfuscation Demo ===")
	fmt.Println()

	// Test various string literals
	fmt.Println("Secret Message:", secretMessage)
	fmt.Println("API Key:", apiKey)
	fmt.Println("Password:", password)
	fmt.Println("Database URL:", databaseURL)
	fmt.Println("Credentials:", string(credentials))

	// Test string operations
	message := "Hello, " + "ASCON" + "!"
	fmt.Println("Concatenated:", message)

	// Test byte slices
	data := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f} // "Hello"
	fmt.Println("Byte slice:", string(data))

	// Test large literal
	longString := `Lorem ipsum dolor sit amet, consectetur adipiscing elit. 
Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. 
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.
This text is long enough to trigger ASCON obfuscation with high probability!`
	fmt.Println("Long string length:", len(longString))

	fmt.Println()
	fmt.Println("✅ All literals processed successfully!")
}
