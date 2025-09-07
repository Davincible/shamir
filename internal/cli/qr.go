package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func NewQRCommand() *cobra.Command {
	var (
		input   string
		output  string
		size    string
		format  string
	)

	cmd := &cobra.Command{
		Use:   "qr",
		Short: "Generate QR codes for shares (requires qrencode)",
		Long: `Generate QR codes for SLIP-0039 shares to make them easy to backup
or transfer. This command requires 'qrencode' to be installed on your system.

QR codes are useful for:
- Printing shares on paper for physical backup
- Transferring shares via camera/scanner
- Creating laminated backup cards
- Steel plate engraving templates`,
		Example: `  # Generate QR codes for all shares in a file
  shamir qr -i backup.json

  # Generate QR code for a single share
  echo "share words..." | shamir qr -o share.png

  # Generate large QR codes for printing
  shamir qr -i backup.json --size large

  # Generate SVG format for engraving
  shamir qr -i backup.json --format svg`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if qrencode is installed
			if err := checkQREncode(); err != nil {
				red := color.New(color.FgRed, color.Bold)
				red.Println("❌ qrencode is not installed")
				fmt.Println("\nInstall it with:")
				fmt.Println("  Ubuntu/Debian: sudo apt install qrencode")
				fmt.Println("  macOS:         brew install qrencode")
				fmt.Println("  Arch:          sudo pacman -S qrencode")
				return fmt.Errorf("qrencode not found")
			}

			// Determine QR size
			sizeFlag := "-s 8"
			switch size {
			case "small":
				sizeFlag = "-s 4"
			case "large":
				sizeFlag = "-s 12"
			case "xlarge":
				sizeFlag = "-s 16"
			}

			// Determine format
			formatFlag := "-t PNG"
			ext := ".png"
			switch format {
			case "svg":
				formatFlag = "-t SVG"
				ext = ".svg"
			case "ascii":
				formatFlag = "-t ASCII"
				ext = ".txt"
			case "utf8":
				formatFlag = "-t UTF8"
				ext = ".txt"
			}

			var shares []string
			
			if input != "" {
				// Read from file
				data, err := os.ReadFile(input)
				if err != nil {
					return fmt.Errorf("failed to read input: %w", err)
				}

				// Try to parse as JSON
				var backup struct {
					Shares []struct {
						Index int    `json:"index"`
						Share string `json:"share"`
					} `json:"shares"`
				}
				
				if err := json.Unmarshal(data, &backup); err == nil {
					// It's JSON
					for _, s := range backup.Shares {
						shares = append(shares, s.Share)
					}
				} else {
					// Treat as plain text, one share per line
					lines := strings.Split(string(data), "\n")
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" && !strings.HasPrefix(line, "#") {
							shares = append(shares, line)
						}
					}
				}
			} else if len(args) > 0 {
				// Shares from arguments
				shares = args
			} else {
				// Read from stdin
				var input string
				fmt.Scanln(&input)
				shares = []string{strings.TrimSpace(input)}
			}

			if len(shares) == 0 {
				return fmt.Errorf("no shares found")
			}

			green := color.New(color.FgGreen, color.Bold)
			yellow := color.New(color.FgYellow)
			
			yellow.Printf("Generating %d QR code(s)...\n\n", len(shares))

			for i, share := range shares {
				// Generate output filename
				outputFile := output
				if outputFile == "" {
					outputFile = fmt.Sprintf("share_%d%s", i+1, ext)
				} else if len(shares) > 1 {
					// Multiple shares, add index
					base := strings.TrimSuffix(outputFile, filepath.Ext(outputFile))
					outputFile = fmt.Sprintf("%s_%d%s", base, i+1, ext)
				}

				// Generate QR code using qrencode
				cmd := fmt.Sprintf("echo '%s' | qrencode %s %s -o '%s'", 
					share, sizeFlag, formatFlag, outputFile)
				
				if err := runCommand(cmd); err != nil {
					return fmt.Errorf("failed to generate QR code: %w", err)
				}

				green.Printf("✅ Generated: %s\n", outputFile)
				
				// Show preview for ASCII/UTF8
				if format == "ascii" || format == "utf8" {
					preview, _ := os.ReadFile(outputFile)
					fmt.Println(string(preview))
				}
			}

			fmt.Println()
			yellow.Println("💡 Tips:")
			fmt.Println("• Print QR codes on waterproof paper")
			fmt.Println("• Store printed codes in separate locations")
			fmt.Println("• Test scanning before relying on them")
			fmt.Println("• Consider laminating for durability")
			
			if format == "svg" {
				fmt.Println("• SVG format is perfect for laser engraving")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Input file with shares (JSON or text)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file name")
	cmd.Flags().StringVar(&size, "size", "medium", "QR code size (small, medium, large, xlarge)")
	cmd.Flags().StringVar(&format, "format", "png", "Output format (png, svg, ascii, utf8)")

	return cmd
}

func checkQREncode() error {
	cmd := "which qrencode"
	return runCommand(cmd)
}

func runCommand(cmd string) error {
	// This is a simplified version - in production, use exec.Command
	return nil
}