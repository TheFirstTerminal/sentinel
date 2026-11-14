package config

import _ "embed"

// Example is a commented config file with the main settings
// (written by `sentinel init`).
//
//go:embed sentinel.example.yaml
var Example []byte
