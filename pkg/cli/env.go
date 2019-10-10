package cli

import (
	"os"
	"strconv"
)

// GetEnvWithDefault get environment variable with fallback on a default value
func GetEnvWithDefault(env string, def string) string {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	return val
}

// GetBoolEnvWithDefault get a bool environment variable with a bool fallback on a default value
func GetBoolEnvWithDefault(env string, def bool) bool {
	val := os.Getenv(env)
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return def
	}
	return b
}
