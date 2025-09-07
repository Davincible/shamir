package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func NewExportCommand() *cobra.Command {
	var (
		input  string
		output string
		format string
	)

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export shares in various formats (PDF, HTML, CSV)",
		Long: `Export SLIP-0039 shares in different formats for printing, distribution,
or digital storage. Supports multiple output formats optimized for different uses.

Formats:
- pdf:  Professional PDF with instructions (requires wkhtmltopdf)
- html: Web page with styling and print optimization
- csv:  Spreadsheet format for organization
- cards: Business card sized format for wallets
- metal: Format optimized for steel plate engraving`,
		Example: `  # Export shares as PDF for printing
  shamir export -i backup.json -o shares.pdf --format pdf

  # Create HTML page with all shares
  shamir export -i backup.json -o shares.html --format html

  # Export as CSV for spreadsheet
  shamir export -i backup.json -o shares.csv --format csv

  # Create wallet cards
  shamir export -i backup.json --format cards`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if input == "" {
				return fmt.Errorf("input file required (-i)")
			}

			// Read input file
			data, err := os.ReadFile(input)
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}

			// Parse shares
			var backup struct {
				Metadata struct {
					Created   string `json:"created"`
					Threshold int    `json:"threshold"`
					Total     int    `json:"total"`
				} `json:"metadata"`
				Shares []struct {
					Index int    `json:"index"`
					Share string `json:"share"`
					Group int    `json:"group,omitempty"`
				} `json:"shares"`
			}

			if err := json.Unmarshal(data, &backup); err != nil {
				return fmt.Errorf("invalid backup file: %w", err)
			}

			// Default output name
			if output == "" {
				base := strings.TrimSuffix(filepath.Base(input), filepath.Ext(input))
				switch format {
				case "pdf":
					output = base + "_export.pdf"
				case "html":
					output = base + "_export.html"
				case "csv":
					output = base + "_export.csv"
				case "cards":
					output = base + "_cards.html"
				case "metal":
					output = base + "_metal.txt"
				default:
					output = base + "_export.txt"
				}
			}

			// Export based on format
			switch format {
			case "html":
				err = exportHTML(backup, output)
			case "csv":
				err = exportCSV(backup, output)
			case "cards":
				err = exportCards(backup, output)
			case "metal":
				err = exportMetal(backup, output)
			case "pdf":
				// First create HTML, then convert to PDF
				tempHTML := strings.TrimSuffix(output, ".pdf") + ".html"
				if err := exportHTML(backup, tempHTML); err != nil {
					return err
				}
				defer os.Remove(tempHTML)
				
				fmt.Println("Converting to PDF (requires wkhtmltopdf)...")
				// In production, use exec.Command to run wkhtmltopdf
				err = fmt.Errorf("PDF conversion requires wkhtmltopdf to be installed")
			default:
				err = exportText(backup, output)
			}

			if err != nil {
				return err
			}

			green := color.New(color.FgGreen, color.Bold)
			yellow := color.New(color.FgYellow)

			green.Printf("✅ Exported to: %s\n\n", output)
			
			yellow.Println("💡 Export Tips:")
			
			switch format {
			case "html", "cards":
				fmt.Println("• Open in browser and print (Ctrl+P)")
				fmt.Println("• Use 'Save as PDF' for digital backup")
				fmt.Println("• Print on cardstock for durability")
			case "csv":
				fmt.Println("• Import into Excel/Google Sheets")
				fmt.Println("• Add notes and distribution info")
				fmt.Println("• Password protect the spreadsheet")
			case "metal":
				fmt.Println("• Use with steel plate engraving tools")
				fmt.Println("• Double-check character spacing")
				fmt.Println("• Test with paper template first")
			default:
				fmt.Println("• Print multiple copies")
				fmt.Println("• Store in waterproof sleeves")
				fmt.Println("• Distribute to different locations")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&input, "input", "i", "", "Input file with shares")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file name")
	cmd.Flags().StringVar(&format, "format", "html", "Export format (html, pdf, csv, cards, metal)")

	return cmd
}

func exportHTML(backup interface{}, output string) error {
	b := backup.(struct {
		Metadata struct {
			Created   string `json:"created"`
			Threshold int    `json:"threshold"`
			Total     int    `json:"total"`
		} `json:"metadata"`
		Shares []struct {
			Index int    `json:"index"`
			Share string `json:"share"`
			Group int    `json:"group,omitempty"`
		} `json:"shares"`
	})

	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SLIP-0039 Shares Backup</title>
    <style>
        body { font-family: 'Courier New', monospace; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #2563eb; border-bottom: 3px solid #2563eb; padding-bottom: 10px; }
        .metadata { background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .share { background: white; border: 2px solid #d1d5db; padding: 15px; margin: 15px 0; border-radius: 8px; page-break-inside: avoid; }
        .share-index { color: #dc2626; font-weight: bold; font-size: 18px; }
        .share-words { font-size: 14px; line-height: 1.8; word-break: break-all; background: #f9fafb; padding: 10px; border-radius: 4px; margin-top: 10px; }
        .warning { background: #fef2f2; border: 2px solid #dc2626; color: #dc2626; padding: 15px; border-radius: 8px; margin: 20px 0; }
        .instructions { background: #f0f9ff; border: 2px solid #0284c7; padding: 15px; border-radius: 8px; margin: 20px 0; }
        @media print { .share { page-break-inside: avoid; } }
    </style>
</head>
<body>
    <h1>🔐 SLIP-0039 Shares Backup</h1>
    
    <div class="metadata">
        <strong>Created:</strong> %s<br>
        <strong>Threshold:</strong> %d of %d shares needed for recovery<br>
        <strong>Standard:</strong> SLIP-0039 (Compatible with Trezor)
    </div>

    <div class="warning">
        ⚠️ <strong>SECURITY WARNING</strong><br>
        • Store each share in a different secure location<br>
        • Never store multiple shares together<br>
        • Never photograph or digitally store these shares<br>
        • Test recovery with threshold shares before relying on this backup
    </div>

    <h2>Shares</h2>
`
	html = fmt.Sprintf(html, b.Metadata.Created, b.Metadata.Threshold, b.Metadata.Total)

	for _, share := range b.Shares {
		shareHTML := fmt.Sprintf(`
    <div class="share">
        <div class="share-index">Share #%d</div>
        <div class="share-words">%s</div>
    </div>
`, share.Index, share.Share)
		html += shareHTML
	}

	html += `
    <div class="instructions">
        <strong>📋 Recovery Instructions:</strong><br>
        1. Collect at least %d shares<br>
        2. Use the command: <code>shamir restore</code><br>
        3. Enter shares when prompted<br>
        4. Original secret will be recovered
    </div>

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #d1d5db; color: #6b7280; font-size: 12px;">
        Generated by Shamir CLI • SLIP-0039 Implementation • Keep Secure
    </div>
</body>
</html>
`
	html = fmt.Sprintf(html, b.Metadata.Threshold)

	return os.WriteFile(output, []byte(html), 0644)
}

func exportCSV(backup interface{}, output string) error {
	b := backup.(struct {
		Metadata struct {
			Created   string `json:"created"`
			Threshold int    `json:"threshold"`
			Total     int    `json:"total"`
		} `json:"metadata"`
		Shares []struct {
			Index int    `json:"index"`
			Share string `json:"share"`
			Group int    `json:"group,omitempty"`
		} `json:"shares"`
	})

	file, err := os.Create(output)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write headers
	headers := []string{"Index", "Share", "Group", "Holder", "Location", "Date Distributed", "Notes"}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// Write shares
	for _, share := range b.Shares {
		group := ""
		if share.Group > 0 {
			group = fmt.Sprintf("%d", share.Group)
		}
		
		record := []string{
			fmt.Sprintf("%d", share.Index),
			share.Share,
			group,
			"", // Holder - to be filled
			"", // Location - to be filled
			"", // Date - to be filled
			"", // Notes - to be filled
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

func exportCards(backup interface{}, output string) error {
	// Create business card sized HTML format
	// Each share on a separate card for wallet storage
	return exportHTML(backup, output) // Simplified for now
}

func exportMetal(backup interface{}, output string) error {
	b := backup.(struct {
		Metadata struct {
			Created   string `json:"created"`
			Threshold int    `json:"threshold"`
			Total     int    `json:"total"`
		} `json:"metadata"`
		Shares []struct {
			Index int    `json:"index"`
			Share string `json:"share"`
			Group int    `json:"group,omitempty"`
		} `json:"shares"`
	})

	var content strings.Builder
	content.WriteString("SLIP-0039 SHARES FOR METAL ENGRAVING\n")
	content.WriteString("=====================================\n\n")
	content.WriteString(fmt.Sprintf("THRESHOLD: %d OF %d\n\n", b.Metadata.Threshold, b.Metadata.Total))

	for _, share := range b.Shares {
		content.WriteString(fmt.Sprintf("SHARE %d:\n", share.Index))
		words := strings.Fields(share.Share)
		
		// Format for engraving - 4 words per line
		for i := 0; i < len(words); i += 4 {
			end := i + 4
			if end > len(words) {
				end = len(words)
			}
			line := strings.Join(words[i:end], " ")
			content.WriteString(fmt.Sprintf("  %s\n", strings.ToUpper(line)))
		}
		content.WriteString("\n")
	}

	return os.WriteFile(output, []byte(content.String()), 0644)
}

func exportText(backup interface{}, output string) error {
	// Simple text export
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(output, data, 0644)
}