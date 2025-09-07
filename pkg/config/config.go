// Package config provides configuration management for the Shamir CLI tool
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Davincible/shamir/pkg/crypto/secretsharing"
)

// Config represents the main configuration structure
type Config struct {
	Version  string          `json:"version"`
	Defaults DefaultSettings `json:"defaults"`
	Schemes  SchemeSettings  `json:"schemes"`
	Security SecurityConfig  `json:"security"`
	UI       UIConfig        `json:"ui"`
	Storage  StorageConfig   `json:"storage"`
	Advanced AdvancedConfig  `json:"advanced"`
}

// DefaultSettings contains default values for common operations
type DefaultSettings struct {
	Scheme         string `json:"scheme"`          // Default: slip039
	Threshold      int    `json:"threshold"`       // Default: 2
	Shares         int    `json:"shares"`          // Default: 3
	GroupThreshold int    `json:"group_threshold"` // Default: 1
	UseMnemonic    bool   `json:"use_mnemonic"`    // Default: true
	Interactive    bool   `json:"interactive"`     // Default: false
}

// SchemeSettings contains scheme-specific configurations
type SchemeSettings struct {
	SLIP039 SLIP039Config `json:"slip039"`
	PVSS    PVSSConfig    `json:"pvss"`
}

// SLIP039Config contains SLIP-0039 specific settings
type SLIP039Config struct {
	IterationExponent int    `json:"iteration_exponent"` // Default: 1 (20000 iterations)
	DefaultGroups     string `json:"default_groups"`     // Default group configuration
	WordList          string `json:"wordlist"`           // Custom wordlist path
	Extendable        bool   `json:"extendable"`         // Allow share extension
}

// PVSSConfig contains PVSS specific settings
type PVSSConfig struct {
	CurveType        string `json:"curve_type"`         // Default: p256
	EnableMnemonic   bool   `json:"enable_mnemonic"`    // Default: true
	ProofValidation  bool   `json:"proof_validation"`   // Default: true
	CommitmentFormat string `json:"commitment_format"`  // json, hex, base64
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	RequirePassphrase   bool   `json:"require_passphrase"`    // Force passphrase use
	MinPassphraseLength int    `json:"min_passphrase_length"` // Minimum passphrase length
	WipeMemory          bool   `json:"wipe_memory"`           // Secure memory wiping
	DisableClipboard    bool   `json:"disable_clipboard"`     // Prevent clipboard usage
	WarningLevel        string `json:"warning_level"`         // none, normal, paranoid
	AutoVerify          bool   `json:"auto_verify"`           // Auto-verify after split
}

// UIConfig contains user interface settings
type UIConfig struct {
	UseColor         bool   `json:"use_color"`          // Enable colored output
	ProgressBar      bool   `json:"progress_bar"`       // Show progress indicators
	Verbosity        string `json:"verbosity"`          // quiet, normal, verbose
	DateFormat       string `json:"date_format"`        // Date format string
	AutoComplete     bool   `json:"auto_complete"`      // Enable auto-completion
	ConfirmActions   bool   `json:"confirm_actions"`    // Require confirmation
	ShowExamples     bool   `json:"show_examples"`      // Show examples in help
}

// StorageConfig contains storage-related settings
type StorageConfig struct {
	DefaultPath      string `json:"default_path"`       // Default storage directory
	AutoSave         bool   `json:"auto_save"`          // Auto-save shares
	FilePermissions  string `json:"file_permissions"`   // Default file permissions
	BackupEnabled    bool   `json:"backup_enabled"`     // Enable automatic backups
	BackupPath       string `json:"backup_path"`        // Backup directory
	EncryptStorage   bool   `json:"encrypt_storage"`    // Encrypt saved shares
	CompressionLevel int    `json:"compression_level"`  // 0-9 compression level
}

// AdvancedConfig contains advanced/experimental features
type AdvancedConfig struct {
	EnabledExperimental   bool              `json:"enable_experimental"`    // Enable experimental features
	NetworkRecovery       bool              `json:"network_recovery"`       // Enable network-based recovery
	HSMIntegration        bool              `json:"hsm_integration"`        // Hardware Security Module support
	MultiSignature        bool              `json:"multi_signature"`        // Multi-signature support
	ThresholdSignatures   bool              `json:"threshold_signatures"`   // Threshold signature schemes
	CustomSchemes         []CustomScheme    `json:"custom_schemes"`         // User-defined schemes
	Plugins               []string          `json:"plugins"`                // External plugin paths
}

// CustomScheme represents a user-defined secret sharing scheme
type CustomScheme struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Parameters  map[string]interface{} `json:"parameters"`
	ScriptPath  string                 `json:"script_path"`
}

// ShareProfile represents a saved configuration profile for quick access
type ShareProfile struct {
	Name        string                          `json:"name"`
	Description string                          `json:"description"`
	Scheme      secretsharing.SchemeType        `json:"scheme"`
	Config      secretsharing.SecretSharingConfig `json:"config"`
	Tags        []string                        `json:"tags"`
}

// ConfigManager manages configuration loading and saving
type ConfigManager struct {
	config     *Config
	configPath string
	profiles   map[string]*ShareProfile
}

// NewConfigManager creates a new configuration manager
func NewConfigManager() (*ConfigManager, error) {
	cm := &ConfigManager{
		profiles: make(map[string]*ShareProfile),
	}
	
	// Determine config path
	configPath, err := getConfigPath()
	if err != nil {
		return nil, err
	}
	cm.configPath = configPath
	
	// Load or create default config
	if err := cm.LoadConfig(); err != nil {
		// Create default config if doesn't exist
		cm.config = DefaultConfig()
		if err := cm.SaveConfig(); err != nil {
			return nil, fmt.Errorf("failed to save default config: %w", err)
		}
	}
	
	// Load profiles
	if err := cm.LoadProfiles(); err != nil {
		// Profiles are optional, so we don't fail here
		cm.profiles = make(map[string]*ShareProfile)
	}
	
	return cm, nil
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Version: "1.0.0",
		Defaults: DefaultSettings{
			Scheme:         "slip039",
			Threshold:      2,
			Shares:         3,
			GroupThreshold: 1,
			UseMnemonic:    true,
			Interactive:    false,
		},
		Schemes: SchemeSettings{
			SLIP039: SLIP039Config{
				IterationExponent: 1,
				DefaultGroups:     "",
				WordList:          "",
				Extendable:        false,
			},
			PVSS: PVSSConfig{
				CurveType:        "p256",
				EnableMnemonic:   true,
				ProofValidation:  true,
				CommitmentFormat: "json",
			},
		},
		Security: SecurityConfig{
			RequirePassphrase:   false,
			MinPassphraseLength: 8,
			WipeMemory:          true,
			DisableClipboard:    false,
			WarningLevel:        "normal",
			AutoVerify:          false,
		},
		UI: UIConfig{
			UseColor:       true,
			ProgressBar:    true,
			Verbosity:      "normal",
			DateFormat:     "2006-01-02 15:04:05",
			AutoComplete:   true,
			ConfirmActions: true,
			ShowExamples:   true,
		},
		Storage: StorageConfig{
			DefaultPath:      "~/.shamir/shares",
			AutoSave:         false,
			FilePermissions:  "0600",
			BackupEnabled:    false,
			BackupPath:       "~/.shamir/backups",
			EncryptStorage:   false,
			CompressionLevel: 6,
		},
		Advanced: AdvancedConfig{
			EnabledExperimental:  false,
			NetworkRecovery:      false,
			HSMIntegration:       false,
			MultiSignature:       false,
			ThresholdSignatures:  false,
			CustomSchemes:        []CustomScheme{},
			Plugins:              []string{},
		},
	}
}

// LoadConfig loads the configuration from disk
func (cm *ConfigManager) LoadConfig() error {
	data, err := os.ReadFile(cm.configPath)
	if err != nil {
		return err
	}
	
	config := &Config{}
	if err := json.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}
	
	cm.config = config
	return nil
}

// SaveConfig saves the configuration to disk
func (cm *ConfigManager) SaveConfig() error {
	// Ensure config directory exists
	configDir := filepath.Dir(cm.configPath)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}
	
	// Marshal config to JSON
	data, err := json.MarshalIndent(cm.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// Write to file
	if err := os.WriteFile(cm.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	
	return nil
}

// GetConfig returns the current configuration
func (cm *ConfigManager) GetConfig() *Config {
	return cm.config
}

// SetConfig updates the configuration
func (cm *ConfigManager) SetConfig(config *Config) {
	cm.config = config
}

// LoadProfiles loads saved sharing profiles
func (cm *ConfigManager) LoadProfiles() error {
	profilesPath := filepath.Join(filepath.Dir(cm.configPath), "profiles.json")
	
	data, err := os.ReadFile(profilesPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Profiles file doesn't exist yet
			return nil
		}
		return err
	}
	
	profiles := make(map[string]*ShareProfile)
	if err := json.Unmarshal(data, &profiles); err != nil {
		return fmt.Errorf("failed to parse profiles: %w", err)
	}
	
	cm.profiles = profiles
	return nil
}

// SaveProfiles saves sharing profiles to disk
func (cm *ConfigManager) SaveProfiles() error {
	profilesPath := filepath.Join(filepath.Dir(cm.configPath), "profiles.json")
	
	data, err := json.MarshalIndent(cm.profiles, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profiles: %w", err)
	}
	
	if err := os.WriteFile(profilesPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write profiles: %w", err)
	}
	
	return nil
}

// AddProfile adds a new sharing profile
func (cm *ConfigManager) AddProfile(profile *ShareProfile) error {
	if profile.Name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}
	
	cm.profiles[profile.Name] = profile
	return cm.SaveProfiles()
}

// GetProfile retrieves a sharing profile by name
func (cm *ConfigManager) GetProfile(name string) (*ShareProfile, error) {
	profile, exists := cm.profiles[name]
	if !exists {
		return nil, fmt.Errorf("profile '%s' not found", name)
	}
	return profile, nil
}

// ListProfiles returns all available profiles
func (cm *ConfigManager) ListProfiles() []*ShareProfile {
	profiles := make([]*ShareProfile, 0, len(cm.profiles))
	for _, profile := range cm.profiles {
		profiles = append(profiles, profile)
	}
	return profiles
}

// DeleteProfile removes a sharing profile
func (cm *ConfigManager) DeleteProfile(name string) error {
	if _, exists := cm.profiles[name]; !exists {
		return fmt.Errorf("profile '%s' not found", name)
	}
	
	delete(cm.profiles, name)
	return cm.SaveProfiles()
}

// getConfigPath returns the configuration file path
func getConfigPath() (string, error) {
	// Check for custom config path
	if customPath := os.Getenv("SHAMIR_CONFIG"); customPath != "" {
		return customPath, nil
	}
	
	// Use XDG_CONFIG_HOME if set
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "shamir", "config.json"), nil
	}
	
	// Default to ~/.config/shamir/config.json
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	
	return filepath.Join(homeDir, ".config", "shamir", "config.json"), nil
}

// ApplyDefaults applies default configuration values to a SecretSharingConfig
func (cm *ConfigManager) ApplyDefaults(config *secretsharing.SecretSharingConfig) {
	if config.Scheme == "" {
		config.Scheme = secretsharing.SchemeType(cm.config.Defaults.Scheme)
	}
	
	if config.GroupThreshold == 0 {
		config.GroupThreshold = cm.config.Defaults.GroupThreshold
	}
	
	if len(config.Groups) == 0 {
		config.Groups = []secretsharing.GroupConfiguration{
			{
				MemberThreshold: cm.config.Defaults.Threshold,
				MemberCount:     cm.config.Defaults.Shares,
			},
		}
	}
}

// ValidateConfig validates a configuration against security policies
func (cm *ConfigManager) ValidateConfig(config *secretsharing.SecretSharingConfig) error {
	// Check passphrase requirements
	if cm.config.Security.RequirePassphrase && config.Passphrase == "" {
		return fmt.Errorf("passphrase is required by security policy")
	}
	
	if config.Passphrase != "" && len(config.Passphrase) < cm.config.Security.MinPassphraseLength {
		return fmt.Errorf("passphrase must be at least %d characters", 
			cm.config.Security.MinPassphraseLength)
	}
	
	// Validate thresholds
	for i, group := range config.Groups {
		if group.MemberThreshold <= 0 {
			return fmt.Errorf("group %d: threshold must be positive", i+1)
		}
		if group.MemberThreshold > group.MemberCount {
			return fmt.Errorf("group %d: threshold cannot exceed member count", i+1)
		}
	}
	
	return nil
}