// Package parser provides element parsing utilities for SPDX documents.
package parser

import "time"

// Helpers provides utility methods for extracting values from JSON maps.
type Helpers struct{}

// NewHelpers creates a new Helpers instance.
func NewHelpers() *Helpers {
	return &Helpers{}
}

// GetString extracts a string value from a map by key.
// Returns empty string if key doesn't exist or value is not a string.
func (h *Helpers) GetString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// GetStringSlice extracts a string slice from a map by key.
// Handles both []interface{} and single string values.
func (h *Helpers) GetStringSlice(m map[string]interface{}, key string) []string {
	var result []string

	switch v := m[key].(type) {
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
	case string:
		result = append(result, v)
	}

	return result
}

// GetInt extracts an integer value from a map by key.
// JSON numbers are float64, so this handles the conversion.
func (h *Helpers) GetInt(m map[string]interface{}, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}

// GetFloat extracts a float64 value from a map by key.
func (h *Helpers) GetFloat(m map[string]interface{}, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

// GetBool extracts a boolean value from a map by key.
func (h *Helpers) GetBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

// GetTime parses a time string from a map by key using RFC3339 format.
// Returns zero time if parsing fails or key doesn't exist.
func (h *Helpers) GetTime(m map[string]interface{}, key string) time.Time {
	if v, ok := m[key].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetMap extracts a nested map from a map by key.
// Returns nil if key doesn't exist or value is not a map.
func (h *Helpers) GetMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key].(map[string]interface{}); ok {
		return v
	}
	return nil
}

// GetSlice extracts a slice of interfaces from a map by key.
// Returns nil if key doesn't exist or value is not a slice.
func (h *Helpers) GetSlice(m map[string]interface{}, key string) []interface{} {
	if v, ok := m[key].([]interface{}); ok {
		return v
	}
	return nil
}

// GetStringPrefixed tries the prefixed key first, then falls back to the bare key.
func (h *Helpers) GetStringPrefixed(m map[string]interface{}, prefix, key string) string {
	if v, ok := m[prefix+key].(string); ok {
		return v
	}
	return h.GetString(m, key)
}

// GetStringSlicePrefixed tries the prefixed key first, then falls back to the bare key.
func (h *Helpers) GetStringSlicePrefixed(m map[string]interface{}, prefix, key string) []string {
	if v, ok := m[prefix+key]; ok {
		switch val := v.(type) {
		case []interface{}:
			var result []string
			for _, item := range val {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		case string:
			return []string{val}
		}
	}
	return h.GetStringSlice(m, key)
}

// GetIntPrefixed tries the prefixed key first, then falls back to the bare key.
func (h *Helpers) GetIntPrefixed(m map[string]interface{}, prefix, key string) int {
	if v, ok := m[prefix+key].(float64); ok {
		return int(v)
	}
	return h.GetInt(m, key)
}

// GetFloatPrefixed tries the prefixed key first, then falls back to the bare key.
func (h *Helpers) GetFloatPrefixed(m map[string]interface{}, prefix, key string) float64 {
	if v, ok := m[prefix+key].(float64); ok {
		return v
	}
	return h.GetFloat(m, key)
}

// GetBoolPrefixed tries the prefixed key first, then falls back to the bare key.
func (h *Helpers) GetBoolPrefixed(m map[string]interface{}, prefix, key string) bool {
	if v, ok := m[prefix+key].(bool); ok {
		return v
	}
	return h.GetBool(m, key)
}

// GetTimePrefixed tries the prefixed key first, then falls back to the bare key.
func (h *Helpers) GetTimePrefixed(m map[string]interface{}, prefix, key string) time.Time {
	if v, ok := m[prefix+key].(string); ok {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	}
	return h.GetTime(m, key)
}

// GetMapPrefixed tries the prefixed key first, then falls back to the bare key.
func (h *Helpers) GetMapPrefixed(m map[string]interface{}, prefix, key string) map[string]interface{} {
	if v, ok := m[prefix+key].(map[string]interface{}); ok {
		return v
	}
	return h.GetMap(m, key)
}

// GetSlicePrefixed tries the prefixed key first, then falls back to the bare key.
func (h *Helpers) GetSlicePrefixed(m map[string]interface{}, prefix, key string) []interface{} {
	if v, ok := m[prefix+key].([]interface{}); ok {
		return v
	}
	return h.GetSlice(m, key)
}
