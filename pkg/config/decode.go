package config

import (
	"reflect"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
)

// decodeOptions replaces viper's default decode hooks with the same pair,
// except that a comma-separated string becomes a list of trimmed items.
// viper's own hook splits on "," alone, so "dns: 8.8.8.8, 8.8.4.4" became
// ["8.8.8.8", " 8.8.4.4"] and the second server was dropped as invalid.
var decodeOptions = viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
	mapstructure.StringToTimeDurationHookFunc(),
	stringToTrimmedSliceHook,
))

// stringToTrimmedSliceHook splits a string decoded into a slice on "," and
// trims the space around each item. An empty string is an empty list.
func stringToTrimmedSliceHook(from, to reflect.Kind, data interface{}) (interface{}, error) {
	if from != reflect.String || to != reflect.Slice {
		return data, nil
	}
	raw := data.(string)
	if raw == "" {
		return []string{}, nil
	}
	items := strings.Split(raw, ",")
	for i := range items {
		items[i] = strings.TrimSpace(items[i])
	}
	return items, nil
}
