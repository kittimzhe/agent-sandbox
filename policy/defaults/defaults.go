// Package defaults carries the example policies shipped with the
// runtime: a starting point for an operator to copy and edit, and the
// fixture the tests hold the engine's behavior against.
package defaults

import _ "embed"

//go:embed agent-web.yaml
var Web string

//go:embed agent-dev.yaml
var Dev string

//go:embed agent-ci.yaml
var CI string

// All lists every default policy by name.
var All = map[string]string{
	"agent-web": Web,
	"agent-dev": Dev,
	"agent-ci":  CI,
}
