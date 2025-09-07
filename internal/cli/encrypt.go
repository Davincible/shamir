package cli

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/secure"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

func NewEncryptCommand() *cobra.Command {
	var (
		input       string
		output      string
		mnemonicStr string
		text        string
		armor       bool
	)

	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt files or text using a BIP-39 mnemonic",
		Long: `Encrypt files or text using a BIP-39 mnemonic as the encryption key.
This provides a memorable yet secure way to encrypt sensitive data.

The encryption uses AES-256-GCM with PBKDF2 key derivation from your mnemonic.
You can use any BIP-39 mnemonic (12-24 words) as the encryption key.`,
		Example: `  # Encrypt a file interactively
  shamir encrypt -i document.pdf -o document.pdf.enc

  # Encrypt text from stdin
  echo "secret message" | shamir encrypt --armor

  # Encrypt with specific mnemonic
  shamir encrypt -i file.txt -o file.enc --mnemonic "your twelve word..."

  # Encrypt text directly
  shamir encrypt --text "my secret" --armor`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get mnemonic
			var m *mnemonic.Mnemonic
			var err error

			if mnemonicStr != "" {
				m, err = mnemonic.FromWords(mnemonicStr)
				if err != nil {
					return fmt.Errorf("invalid mnemonic: %w", err)
				}
			} else {
				// Interactive mode
				fmt.Print("Enter mnemonic for encryption (or press Enter to generate new): ")
				reader := bufio.NewReader(os.Stdin)
				words, err := reader.ReadString('\n')
				if err != nil {
					return err
				}
				words = strings.TrimSpace(words)

				if words == "" {
					// Generate new mnemonic
					m, err = mnemonic.NewMnemonic(128) // 12 words for encryption
					if err != nil {
						return fmt.Errorf("failed to generate mnemonic: %w", err)
					}
					
					yellow := color.New(color.FgYellow, color.Bold)
					yellow.Println("\n✨ Generated encryption mnemonic:")
					fmt.Println(m.Words())
					
					red := color.New(color.FgRed, color.Bold)
					red.Println("\n⚠️  SAVE THIS MNEMONIC! You'll need it to decrypt.")
					fmt.Println()
				} else {
					m, err = mnemonic.FromWords(words)
					if err != nil {
						return fmt.Errorf("invalid mnemonic: %w", err)
					}
				}
			}

			// Derive encryption key from mnemonic
			seed := m.Seed()
			defer secure.Zero(seed)
			
			// Use PBKDF2 to derive a 256-bit key
			salt := []byte("shamir-encryption-v1")
			key := pbkdf2.Key(seed, salt, 100000, 32, sha256.New)
			defer secure.Zero(key)

			// Get data to encrypt
			var plaintext []byte
			
			if text != "" {
				plaintext = []byte(text)
			} else if input != "" {
				plaintext, err = os.ReadFile(input)
				if err != nil {
					return fmt.Errorf("failed to read input file: %w", err)
				}
			} else {
				// Read from stdin
				plaintext, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
			}

			// Encrypt data
			ciphertext, err := encryptData(plaintext, key)
			if err != nil {
				return fmt.Errorf("encryption failed: %w", err)
			}

			// Output
			var result []byte
			if armor {
				result = []byte(base64.StdEncoding.EncodeToString(ciphertext))
			} else {
				result = ciphertext
			}

			if output != "" {
				err = os.WriteFile(output, result, 0600)
				if err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
				
				green := color.New(color.FgGreen, color.Bold)
				green.Printf("✅ Encrypted to: %s\n", output)
				
				if armor {
					fmt.Println("📄 Output is base64 encoded (--armor)")
				}
			} else {
				// Write to stdout
				if armor {
					fmt.Println(string(result))
				} else {
					os.Stdout.Write(result)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Input file to encrypt")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file for encrypted data")
	cmd.Flags().StringVar(&mnemonicStr, "mnemonic", "", "BIP-39 mnemonic for encryption")
	cmd.Flags().StringVar(&text, "text", "", "Text to encrypt directly")
	cmd.Flags().BoolVar(&armor, "armor", false, "Output as base64 encoded text")

	return cmd
}

func NewDecryptCommand() *cobra.Command {
	var (
		input       string
		output      string
		mnemonicStr string
		armor       bool
	)

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt files or text using a BIP-39 mnemonic",
		Long: `Decrypt files or text that were encrypted with the 'encrypt' command.
You'll need the same BIP-39 mnemonic that was used for encryption.`,
		Example: `  # Decrypt a file interactively
  shamir decrypt -i document.pdf.enc -o document.pdf

  # Decrypt from stdin
  cat encrypted.txt | shamir decrypt --armor

  # Decrypt with specific mnemonic
  shamir decrypt -i file.enc -o file.txt --mnemonic "your twelve word..."`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Get mnemonic
			var m *mnemonic.Mnemonic
			var err error

			if mnemonicStr != "" {
				m, err = mnemonic.FromWords(mnemonicStr)
				if err != nil {
					return fmt.Errorf("invalid mnemonic: %w", err)
				}
			} else {
				// Interactive mode
				fmt.Print("Enter decryption mnemonic: ")
				passbytes, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return err
				}
				fmt.Println()
				
				m, err = mnemonic.FromWords(string(passbytes))
				secure.Zero(passbytes)
				if err != nil {
					return fmt.Errorf("invalid mnemonic: %w", err)
				}
			}

			// Derive decryption key from mnemonic
			seed := m.Seed()
			defer secure.Zero(seed)
			
			// Use PBKDF2 to derive a 256-bit key
			salt := []byte("shamir-encryption-v1")
			key := pbkdf2.Key(seed, salt, 100000, 32, sha256.New)
			defer secure.Zero(key)

			// Get data to decrypt
			var ciphertext []byte
			
			if input != "" {
				data, err := os.ReadFile(input)
				if err != nil {
					return fmt.Errorf("failed to read input file: %w", err)
				}
				
				if armor {
					ciphertext, err = base64.StdEncoding.DecodeString(string(data))
					if err != nil {
						return fmt.Errorf("failed to decode base64: %w", err)
					}
				} else {
					ciphertext = data
				}
			} else {
				// Read from stdin
				data, err := io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("failed to read from stdin: %w", err)
				}
				
				if armor {
					ciphertext, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
					if err != nil {
						return fmt.Errorf("failed to decode base64: %w", err)
					}
				} else {
					ciphertext = data
				}
			}

			// Decrypt data
			plaintext, err := decryptData(ciphertext, key)
			if err != nil {
				return fmt.Errorf("decryption failed: %w", err)
			}

			// Output
			if output != "" {
				err = os.WriteFile(output, plaintext, 0644)
				if err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
				
				green := color.New(color.FgGreen, color.Bold)
				green.Printf("✅ Decrypted to: %s\n", output)
			} else {
				// Write to stdout
				os.Stdout.Write(plaintext)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Input file to decrypt")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file for decrypted data")
	cmd.Flags().StringVar(&mnemonicStr, "mnemonic", "", "BIP-39 mnemonic for decryption")
	cmd.Flags().BoolVar(&armor, "armor", false, "Input is base64 encoded")

	return cmd
}

func encryptData(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptData(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}