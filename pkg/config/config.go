package config

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/angelfreak/net/pkg/types"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Known valid field names for each config section type
var (
	// Top-level reserved keys (not network names)
	reservedKeys = map[string]bool{
		"common":  true,
		"ignored": true,
		"vpn":     true,
	}

	// Valid fields for CommonConfig
	validCommonFields = map[string]bool{
		"mac":      true,
		"dns":      true,
		"hostname": true,
		"vpn":      true,
	}

	// Valid fields for IgnoredConfig
	validIgnoredFields = map[string]bool{
		"interfaces": true,
	}

	// Valid fields for VPNConfig
	validVPNFields = map[string]bool{
		"type":      true,
		"config":    true,
		"address":   true,
		"interface": true,
		"gateway":   true,
	}

	// Valid fields for NetworkConfig
	validNetworkFields = map[string]bool{
		"interface": true,
		"ssid":      true,
		"psk":       true,
		"wpa":       true,
		"ap-addr":   true,
		"addr":      true,
		"gateway":   true,
		"routes":    true,
		"dns":       true,
		"mac":       true,
		"hostname":  true,
		"vpn":       true,
	}
)

// ValidationError represents a config validation error with suggestions
type ValidationError struct {
	Section    string
	Field      string
	Suggestion string
}

func (e ValidationError) Error() string {
	if e.Suggestion != "" {
		return fmt.Sprintf("unknown field '%s' in %s (did you mean '%s'?)", e.Field, e.Section, e.Suggestion)
	}
	return fmt.Sprintf("unknown field '%s' in %s", e.Field, e.Section)
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var msgs []string
	for _, err := range e {
		msgs = append(msgs, err.Error())
	}
	return "config validation errors:\n  - " + strings.Join(msgs, "\n  - ")
}

// levenshteinDistance calculates the edit distance between two strings
func levenshteinDistance(a, b string) int {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,
				matrix[i][j-1]+1,
				matrix[i-1][j-1]+cost,
			)
		}
	}
	return matrix[len(a)][len(b)]
}

// findSimilarField finds the most similar valid field name
func findSimilarField(field string, validFields map[string]bool) string {
	bestMatch := ""
	bestDistance := 3 // Max distance to consider as a typo

	for valid := range validFields {
		dist := levenshteinDistance(field, valid)
		if dist < bestDistance {
			bestDistance = dist
			bestMatch = valid
		} else if dist == bestDistance && bestMatch != "" {
			// If distance is equal, prefer shorter field name
			// or alphabetically first if same length
			if len(valid) < len(bestMatch) || (len(valid) == len(bestMatch) && valid < bestMatch) {
				bestMatch = valid
			}
		}
	}
	return bestMatch
}

// validateFields checks for unknown fields in a map against valid fields
func validateFields(section string, data map[string]interface{}, validFields map[string]bool) []ValidationError {
	var errors []ValidationError

	for field := range data {
		if !validFields[field] {
			suggestion := findSimilarField(field, validFields)
			errors = append(errors, ValidationError{
				Section:    section,
				Field:      field,
				Suggestion: suggestion,
			})
		}
	}
	return errors
}

// ValidateConfigFile validates a config file for unknown/misspelled fields
func ValidateConfigFile(path string) ValidationErrors {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // File read errors handled elsewhere
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil // Parse errors handled elsewhere
	}

	return validateRawConfig(raw)
}

// validateRawConfig validates a raw config map for unknown fields
func validateRawConfig(raw map[string]interface{}) ValidationErrors {
	var errors ValidationErrors

	for key, value := range raw {
		switch key {
		case "common":
			if commonMap, ok := value.(map[string]interface{}); ok {
				errors = append(errors, validateFields("common", commonMap, validCommonFields)...)
			}
		case "ignored":
			if ignoredMap, ok := value.(map[string]interface{}); ok {
				errors = append(errors, validateFields("ignored", ignoredMap, validIgnoredFields)...)
			}
		case "vpn":
			if vpnMap, ok := value.(map[string]interface{}); ok {
				for vpnName, vpnValue := range vpnMap {
					if vpnConfig, ok := vpnValue.(map[string]interface{}); ok {
						errs := validateFields(fmt.Sprintf("vpn.%s", vpnName), vpnConfig, validVPNFields)
						errors = append(errors, errs...)
					}
				}
			}
		default:
			// It's either a network config or an alias (string value)
			if netMap, ok := value.(map[string]interface{}); ok {
				errs := validateFields(fmt.Sprintf("network '%s'", key), netMap, validNetworkFields)
				errors = append(errors, errs...)
			}
			// String values are aliases, no validation needed
		}
	}

	return errors
}

// commonFirstNames is a list of common first names used for hostname generation
// These are typical names you'd see on a MacBook in a coffee shop
var commonFirstNames = []string{
	"Aaron", "Adam", "Alex", "Amanda", "Amy", "Andrew", "Angela", "Anna",
	"Anthony", "Ashley", "Barbara", "Benjamin", "Beth", "Brandon", "Brian",
	"Brittany", "Brooke", "Cameron", "Carl", "Carla", "Carlos", "Carol",
	"Caroline", "Catherine", "Charles", "Charlotte", "Chris", "Christina",
	"Christine", "Christopher", "Claire", "Cody", "Colin", "Connor", "Corey",
	"Courtney", "Craig", "Crystal", "Cynthia", "Daniel", "Danielle", "David",
	"Deborah", "Dennis", "Derek", "Diana", "Diane", "Donald", "Donna", "Dorothy",
	"Douglas", "Dylan", "Edward", "Elizabeth", "Emily", "Emma", "Eric", "Erica",
	"Erin", "Ethan", "Eugene", "Evan", "Evelyn", "Frank", "Gabriel", "Gary",
	"George", "Grace", "Gregory", "Hailey", "Hannah", "Heather", "Helen",
	"Henry", "Holly", "Isaac", "Isabella", "Jack", "Jackson", "Jacob", "Jacqueline",
	"Jake", "James", "Jamie", "Jane", "Janet", "Janice", "Jason", "Jean",
	"Jeffrey", "Jennifer", "Jeremy", "Jerry", "Jesse", "Jessica", "Jill", "Joan",
	"Joe", "John", "Jonathan", "Jordan", "Jose", "Joseph", "Joshua", "Joyce",
	"Juan", "Judith", "Julia", "Julie", "Justin", "Karen", "Katherine", "Kathleen",
	"Kathryn", "Katie", "Kayla", "Keith", "Kelly", "Kenneth", "Kevin", "Kimberly",
	"Kyle", "Larry", "Laura", "Lauren", "Lawrence", "Leah", "Linda", "Lisa",
	"Logan", "Lori", "Lucas", "Luis", "Luke", "Madison", "Margaret", "Maria",
	"Marie", "Marilyn", "Mark", "Martha", "Martin", "Mary", "Mason", "Matthew",
	"Megan", "Melissa", "Michael", "Michelle", "Mike", "Nancy", "Natalie",
	"Nathan", "Nicholas", "Nicole", "Noah", "Olivia", "Pamela", "Patricia",
	"Patrick", "Paul", "Paula", "Peter", "Philip", "Rachel", "Ralph", "Randy",
	"Raymond", "Rebecca", "Richard", "Robert", "Robin", "Roger", "Ronald", "Rose",
	"Roy", "Russell", "Ruth", "Ryan", "Samantha", "Samuel", "Sandra", "Sara",
	"Sarah", "Scott", "Sean", "Sharon", "Shawn", "Shirley", "Sophia", "Stephanie",
	"Stephen", "Steven", "Susan", "Teresa", "Terry", "Theresa", "Thomas",
	"Tiffany", "Timothy", "Todd", "Tom", "Tony", "Tracy", "Travis", "Tyler",
	"Victoria", "Vincent", "Virginia", "Walter", "Wayne", "William", "Willie",
	"Zachary",
}

// randomFirstName returns a random first name from the commonFirstNames list
func randomFirstName() string {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(commonFirstNames))))
	if err != nil {
		// Fallback to a common name if random fails
		return "John"
	}
	return commonFirstNames[n.Int64()]
}

// Manager implements the ConfigManager interface
type Manager struct {
	config     *types.Config
	logger     types.Logger
	viper      *viper.Viper
	configPath string
}

// NewManager creates a new config manager
func NewManager(logger types.Logger) *Manager {
	return &Manager{
		logger: logger,
	}
}

// LoadConfig loads configuration from the specified path
func (m *Manager) LoadConfig(path string) (*types.Config, error) {
	if m.logger != nil {
		m.logger.Debug("LoadConfig called", "path", path)
	}

	if path == "-" {
		// No config file
		if m.logger != nil {
			m.logger.Debug("Using no config file (path='-')")
		}
		m.config = &types.Config{
			Common:   types.CommonConfig{},
			Ignored:  types.IgnoredConfig{},
			VPN:      make(map[string]types.VPNConfig),
			Networks: make(map[string]types.NetworkConfig),
		}
		return m.config, nil
	}

	// Expand ~ to home directory
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, path[1:])
		if m.logger != nil {
			m.logger.Debug("Expanded ~ path", "expandedPath", path)
		}
	}

	// Default to ~/.net/config.yaml if no path specified
	if path == "" {
		var home string
		var err error

		// Handle sudo execution: use SUDO_USER's home directory instead of root
		// This must come BEFORE checking HOME, because sudo sets HOME=/root
		if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
			if m.logger != nil {
				m.logger.Debug("Running with sudo", "sudoUser", sudoUser)
			}
			// Running with sudo, get the actual user's home directory
			if sudoUser == "root" {
				home = "/root"
			} else {
				home = filepath.Join("/home", sudoUser)
			}
		} else if envHome := os.Getenv("HOME"); envHome != "" {
			// Use HOME if not running with sudo (for testing and normal execution)
			home = envHome
		} else {
			// Fallback to os.UserHomeDir()
			home, err = os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("failed to get home directory: %w", err)
			}
		}
		path = filepath.Join(home, ".net", "config.yaml")
		if m.logger != nil {
			m.logger.Debug("Using default config path", "path", path)
		}
	}

	if m.logger != nil {
		m.logger.Debug("Final config path determined", "path", path)
	}

	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// File doesn't exist, return empty config
		if m.logger != nil {
			m.logger.Debug("Config file does not exist, returning empty config", "path", path)
		}
		m.config = &types.Config{
			Common:   types.CommonConfig{},
			Ignored:  types.IgnoredConfig{},
			VPN:      make(map[string]types.VPNConfig),
			Networks: make(map[string]types.NetworkConfig),
		}
		return m.config, nil
	}

	if m.logger != nil {
		m.logger.Debug("Config file exists and is readable", "path", path)
	}

	v := viper.New()
	v.SetConfigFile(path)

	// Set config type to yaml for files that might not have standard extensions
	if filepath.Ext(path) == ".example" || filepath.Ext(path) == "" {
		v.SetConfigType("yaml")
	}

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if m.logger != nil {
		m.logger.Debug("Config file loaded")
	}

	// Validate config for unknown/misspelled fields
	if validationErrors := ValidateConfigFile(path); len(validationErrors) > 0 {
		return nil, validationErrors
	}

	var config types.Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Initialize maps if nil
	if config.VPN == nil {
		config.VPN = make(map[string]types.VPNConfig)
	}
	if config.Networks == nil {
		config.Networks = make(map[string]types.NetworkConfig)
	}

	// Store viper and path for lazy loading networks
	m.viper = v
	m.configPath = path
	m.config = &config

	// Load all network configs upfront (mapstructure ,inline doesn't work with viper)
	// Networks are all top-level keys that aren't reserved (common, ignored, vpn)
	allKeys := v.AllKeys()
	seenNetworks := make(map[string]bool)
	for _, key := range allKeys {
		// Extract the top-level key (before any dot)
		topKey := key
		if idx := strings.Index(key, "."); idx != -1 {
			topKey = key[:idx]
		}

		// Skip reserved keys and already-processed networks
		if reservedKeys[topKey] || seenNetworks[topKey] {
			continue
		}
		seenNetworks[topKey] = true

		// Try to load as network config
		if v.IsSet(topKey) {
			subV := v.Sub(topKey)
			if subV != nil {
				var netConfig types.NetworkConfig
				if err := subV.Unmarshal(&netConfig); err == nil {
					config.Networks[topKey] = netConfig
					if m.logger != nil {
						m.logger.Debug("Loaded network config", "network", topKey)
					}
				}
			}
		}
	}

	// Warn about plain text credentials after successful load
	m.WarnAboutPlainTextCredentials()

	return &config, nil
}

// GetNetworkConfig returns the configuration for a specific network
func (m *Manager) GetNetworkConfig(name string) (*types.NetworkConfig, error) {
	if m.config == nil || m.viper == nil {
		return nil, fmt.Errorf("config not loaded")
	}

	// Handle hostname substitution
	if strings.Contains(name, "$(hostname)") {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname: %w", err)
		}
		name = strings.ReplaceAll(name, "$(hostname)", hostname)
	}

	// Check if already loaded in cache
	if config, exists := m.config.Networks[name]; exists {
		m.logger.Debug("Network config from cache", "network", name, "ssid", config.SSID)
		return &config, nil
	}

	// Lazy load the specific network from viper
	if !m.viper.IsSet(name) {
		return nil, fmt.Errorf("network configuration '%s' not found", name)
	}

	var netConfig types.NetworkConfig
	subV := m.viper.Sub(name)
	if subV == nil {
		return nil, fmt.Errorf("failed to read network configuration '%s'", name)
	}

	if err := subV.Unmarshal(&netConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal network config '%s': %w", name, err)
	}

	// Cache it for next time
	m.config.Networks[name] = netConfig
	m.logger.Debug("Loaded network config", "network", name, "ssid", netConfig.SSID)

	return &netConfig, nil
}

// GetVPNConfig returns the configuration for a specific VPN
func (m *Manager) GetVPNConfig(name string) (*types.VPNConfig, error) {
	if m.config == nil {
		return nil, fmt.Errorf("config not loaded")
	}

	config, exists := m.config.VPN[name]
	if !exists {
		return nil, fmt.Errorf("VPN configuration '%s' not found", name)
	}

	return &config, nil
}

// MergeWithCommon merges network config with common settings
func (m *Manager) MergeWithCommon(networkName string, config *types.NetworkConfig) *types.NetworkConfig {
	if m.config == nil {
		return config
	}

	merged := *config // Copy

	// Interface is not in common config, it's per-network
	if merged.DNS == nil && m.config.Common.DNS != nil {
		merged.DNS = make([]string, len(m.config.Common.DNS))
		copy(merged.DNS, m.config.Common.DNS)
	}
	if merged.MAC == "" {
		if m.config.Common.MAC != "" {
			merged.MAC = m.config.Common.MAC
		} else {
			// Default to random MAC if nothing specified
			merged.MAC = "random"
		}
	}
	if merged.Hostname == "" {
		merged.Hostname = m.config.Common.Hostname
	}
	// Only inherit VPN from common if not explicitly set in network config
	// This allows networks to disable VPN by setting vpn: (empty/null)
	if merged.VPN == "" {
		// Check if vpn key exists in the network config (even if nil/empty)
		// viper.IsSet() returns false for nil values, so we check the raw map
		vpnExplicitlySet := false
		if m.viper != nil {
			networkMap := m.viper.GetStringMap(networkName)
			_, vpnExplicitlySet = networkMap["vpn"]
		}
		if !vpnExplicitlySet {
			merged.VPN = m.config.Common.VPN
		}
	}

	// Handle hostname template replacement
	if strings.Contains(merged.Hostname, "<name>") {
		// Pick a random common first name to blend in with typical device names
		name := randomFirstName()
		merged.Hostname = strings.ReplaceAll(merged.Hostname, "<name>", name)
	}

	return &merged
}

// GetIgnoredInterfaces returns the list of ignored interfaces
func (m *Manager) GetIgnoredInterfaces() []string {
	if m.config == nil {
		return nil
	}
	return m.config.Ignored.Interfaces
}

// GetConfig returns the loaded configuration
func (m *Manager) GetConfig() *types.Config {
	return m.config
}

// WarnAboutPlainTextCredentials checks the loaded config for plain text
// credentials and logs warnings about security implications.
//
// Security note: Storing passwords and private keys in plain text config files
// poses security risks. Consider:
//   - Using file permissions (chmod 600) to restrict access to config files
//   - Storing sensitive credentials in separate files referenced by path
//   - Using environment variables for sensitive values
//   - For VPNs, use separate key files rather than inline config
func (m *Manager) WarnAboutPlainTextCredentials() {
	if m.config == nil || m.logger == nil {
		return
	}

	// Check for plain text WiFi passwords (PSK fields)
	for name, network := range m.config.Networks {
		if network.PSK != "" {
			m.logger.Warn("WiFi password for network is stored in plain text",
				"network", name,
				"suggestion", "Consider using file permissions (chmod 600) to protect your config file")
		}
	}

	// Check for plain text VPN private keys in inline config
	for name, vpn := range m.config.VPN {
		if containsPrivateKey(vpn.Config) {
			m.logger.Warn("VPN contains private key in plain text config",
				"vpn", name,
				"suggestion", "Consider storing keys in separate files with restricted permissions")
		}
	}
}

// containsPrivateKey checks if a VPN config string contains inline private keys
func containsPrivateKey(config string) bool {
	if config == "" {
		return false
	}

	// Check for common private key indicators in WireGuard and OpenVPN configs
	privateKeyIndicators := []string{
		"PrivateKey",     // WireGuard
		"<key>",          // OpenVPN inline key
		"-----BEGIN",     // PEM format keys (OpenVPN)
		"BEGIN PRIVATE",  // Various private key formats
		"BEGIN RSA PRIV", // RSA private key
		"BEGIN EC PRIV",  // EC private key
	}

	for _, indicator := range privateKeyIndicators {
		if strings.Contains(config, indicator) {
			return true
		}
	}

	return false
}
