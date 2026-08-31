package pipeline

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// The connector package schema this server validates. A package naming a
// different one expects semantics this code does not check, so it is rejected
// rather than accepted on the assumption that the shapes happen to line up.
// Same rule as AgentPluginSchema, and for the same reason.
const ConnectorSchema = "https://nanoinfra.org/schemas/connector/1.0.0/connector.schema.json"

// RootConnectorFile is the file whose presence marks an archive as a connector
// package rather than a skill or an Agent Plugins package.
const RootConnectorFile = "connector.json"

// KindConnector is the third archive kind. A skill is text the agent reads; an
// Agent Plugin may declare an MCP server; a connector is a *declaration of
// requests a deployment will make with a live credential*. The listing has to
// say which one a reader is installing, which is why this is a kind and not a
// directory convention.
const KindConnector = "connector"

// The capability classes a connector operation may declare. Fixed, and mirrored
// from `CAPABILITY_CLASSES` in nanoinfra/agent/tools/capabilities.py: a package
// that could name its own class would be a package that decides what the gate
// asks about.
var connectorClasses = map[string]bool{
	"read":              true,
	"mutate.local":      true,
	"mutate.inventory":  true,
	"mutate.remote":     true,
	"credential.access": true,
}

// Methods that write. A `read` class on one of these is refused, the same
// load-time rule the client enforces in nanoinfra/connectors/contracts.py --
// stated twice on purpose, because a catalog that published such a package
// would be handing every installer a refusal.
var connectorWritingMethods = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
}

// MaxConnectorOperations bounds the declaration. A package with more operations
// than this is not a connector, and the review surface has to stay readable.
const MaxConnectorOperations = 64

// connectorManifest is the subset of connector.json this server validates.
//
// Every field the client validates is validated here too, because a package
// this server published and the client then refused would be a broken listing
// rather than a protected installer. The client re-validates regardless: a
// network response is never trusted because of who served it.
type connectorManifest struct {
	Schema       string               `json:"$schema"`
	Name         string               `json:"name"`
	DisplayName  string               `json:"displayName"`
	Description  string               `json:"description"`
	BaseURL      string               `json:"baseUrl"`
	Credential   connectorCredential  `json:"credential"`
	Operations   []connectorOperation `json:"operations"`
	Dependencies []string             `json:"dependencies"`
	Setup        map[string]any       `json:"setup"`
}

type connectorCredential struct {
	Kind         string              `json:"kind"`
	TokenURL     string              `json:"tokenUrl"`
	Scopes       map[string][]string `json:"scopes"`
	AllowedHosts []string            `json:"allowedHosts"`
}

type connectorOperation struct {
	Name    string `json:"name"`
	Class   string `json:"class"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Summary string `json:"summary"`
}

// validateConnectorPackage validates a connector package and reports what
// approving it would grant.
//
// The review surface is the point of the fields it returns. Approving a
// connector is approving a request this deployment will make with a live
// credential, so an approver needs the operations *with their capability
// classes*, the hosts a token could go to, and the scopes that token would
// carry. A screen that listed only the name would hide all three.
func validateConnectorPackage(reader *zip.Reader, expectedID string) (*Result, error) {
	manifestFile, err := findFile(reader, RootConnectorFile)
	if err != nil {
		return nil, err
	}
	raw, err := readEntryLimited(manifestFile, MaxUnpackedBytes)
	if err != nil {
		return nil, fail("%s could not be read: %v", RootConnectorFile, err)
	}

	// Decoded twice: once to reject a non-object root, once for the fields.
	// json.Unmarshal into a struct accepts a JSON array as "no fields set".
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fail("%s is not valid JSON: %v", RootConnectorFile, err)
	}
	if _, ok := root.(map[string]any); !ok {
		return nil, fail("%s must contain a JSON object", RootConnectorFile)
	}
	var manifest connectorManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fail("%s is not a valid manifest: %v", RootConnectorFile, err)
	}

	if manifest.Schema != ConnectorSchema {
		return nil, fail("%s must declare $schema %q", RootConnectorFile, ConnectorSchema)
	}
	if !ValidPluginID(manifest.Name) {
		return nil, fail(
			"%s name %q is not a valid connector identity: use lowercase letters, digits, "+
				"and single dots or hyphens between segments",
			RootConnectorFile, manifest.Name,
		)
	}
	if expectedID != "" && manifest.Name != expectedID {
		return nil, fail(
			"%s name %q does not match submitted id %q",
			RootConnectorFile, manifest.Name, expectedID,
		)
	}
	if len(manifest.Dependencies) > 0 {
		// A declared dependency means the package expects code to run, and this
		// format runs none. Refused rather than dropped: a package whose
		// dependencies were silently ignored would fail at its first call
		// instead of here, where somebody is reading.
		return nil, fail(
			"%s declares dependencies, and a declarative connector package runs no code",
			RootConnectorFile,
		)
	}
	if err := refuseExecutableEntries(reader); err != nil {
		return nil, err
	}

	baseHost, err := connectorHost(manifest.BaseURL)
	if err != nil {
		return nil, fail("%s baseUrl is invalid: %v", RootConnectorFile, err)
	}
	allowed, err := validateConnectorHosts(manifest.Credential, baseHost)
	if err != nil {
		return nil, err
	}
	operations, classes, err := validateConnectorOperations(manifest.Operations)
	if err != nil {
		return nil, err
	}
	scopes := validateConnectorScopes(manifest.Credential)

	return &Result{
		Kind: KindConnector,
		Metadata: Metadata{
			Name:        manifest.Name,
			Description: manifest.Description,
		},
		ConnectorOperations: operations,
		ConnectorClasses:    classes,
		ConnectorHosts:      allowed,
		ConnectorScopes:     scopes,
	}, nil
}

// connectorHost returns the host of an https URL, or an error.
func connectorHost(raw string) (string, error) {
	if !strings.HasPrefix(raw, "https://") {
		return "", fmt.Errorf("must be https: a token travels on it")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a URL")
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("names no host")
	}
	return strings.ToLower(parsed.Hostname()), nil
}

// validateConnectorHosts checks the credential's declared hosts and returns
// them, sorted.
//
// A package that holds a token and names no hosts is a package that can send it
// anywhere, so a credential of any kind must name them -- and the baseUrl's own
// host has to be among them, or the package contradicts its own declaration.
func validateConnectorHosts(credential connectorCredential, baseHost string) ([]string, error) {
	kind := credential.Kind
	if kind == "" {
		kind = "none"
	}
	switch kind {
	case "none", "oauth2", "api_key":
	default:
		return nil, fail("%s credential.kind %q is not one of none, oauth2, api_key", RootConnectorFile, kind)
	}
	hosts := make([]string, 0, len(credential.AllowedHosts))
	seen := map[string]bool{}
	for _, host := range credential.AllowedHosts {
		normalized := strings.ToLower(strings.TrimSpace(host))
		if normalized == "" {
			return nil, fail("%s credential.allowedHosts holds an empty entry", RootConnectorFile)
		}
		if strings.Contains(normalized, "*") {
			// A wildcard is the kind of convenience that makes the check
			// decorative, and this list is what stops a package sending a live
			// token to a host nobody reviewed.
			return nil, fail(
				"%s credential.allowedHosts must name exact hosts, not patterns like %q",
				RootConnectorFile, host,
			)
		}
		if !seen[normalized] {
			seen[normalized] = true
			hosts = append(hosts, normalized)
		}
	}
	if kind == "none" {
		return hosts, nil
	}
	if len(hosts) == 0 {
		return nil, fail(
			"%s credential.allowedHosts must name the hosts this package may address: a package "+
				"that holds a token and names no hosts can send it anywhere",
			RootConnectorFile,
		)
	}
	if !seen[baseHost] {
		return nil, fail(
			"%s declares baseUrl host %q, which is not in credential.allowedHosts %v",
			RootConnectorFile, baseHost, hosts,
		)
	}
	sort.Strings(hosts)
	return hosts, nil
}

// validateConnectorOperations checks each operation and returns the review
// lines plus the distinct capability classes, both sorted.
func validateConnectorOperations(operations []connectorOperation) ([]string, []string, error) {
	if len(operations) == 0 {
		return nil, nil, fail("%s declares no operations, so it grants nothing", RootConnectorFile)
	}
	if len(operations) > MaxConnectorOperations {
		return nil, nil, fail(
			"%s declares %d operations, above the maximum of %d",
			RootConnectorFile, len(operations), MaxConnectorOperations,
		)
	}
	lines := make([]string, 0, len(operations))
	classSet := map[string]bool{}
	names := map[string]bool{}
	for _, op := range operations {
		if op.Name == "" {
			return nil, nil, fail("%s declares an operation with no name", RootConnectorFile)
		}
		if names[op.Name] {
			return nil, nil, fail("%s declares operation %q twice", RootConnectorFile, op.Name)
		}
		names[op.Name] = true
		if !connectorClasses[op.Class] {
			return nil, nil, fail(
				"%s operation %q declares class %q, which is not a capability class",
				RootConnectorFile, op.Name, op.Class,
			)
		}
		method := strings.ToUpper(op.Method)
		if method == "" {
			return nil, nil, fail("%s operation %q declares no method", RootConnectorFile, op.Name)
		}
		if op.Class == "read" && connectorWritingMethods[method] {
			return nil, nil, fail(
				"%s operation %q declares class read on a %s, which writes",
				RootConnectorFile, op.Name, method,
			)
		}
		if !strings.HasPrefix(op.Path, "/") {
			return nil, nil, fail(
				"%s operation %q path %q must start with /: an absolute URL would route a token "+
					"past the host check",
				RootConnectorFile, op.Name, op.Path,
			)
		}
		classSet[op.Class] = true
		// The line an approver reads. The class is first because it is the part
		// being approved.
		lines = append(lines, fmt.Sprintf("%s %s %s %s", op.Class, method, op.Path, op.Name))
	}
	classes := make([]string, 0, len(classSet))
	for class := range classSet {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	sort.Strings(lines)
	return lines, classes, nil
}

// validateConnectorScopes flattens the per-class scopes into the sorted set a
// token could carry.
func validateConnectorScopes(credential connectorCredential) []string {
	seen := map[string]bool{}
	scopes := make([]string, 0)
	for _, values := range credential.Scopes {
		for _, scope := range values {
			trimmed := strings.TrimSpace(scope)
			if trimmed == "" || seen[trimmed] {
				continue
			}
			seen[trimmed] = true
			scopes = append(scopes, trimmed)
		}
	}
	sort.Strings(scopes)
	return scopes
}

// refuseExecutableEntries rejects a connector archive that ships something
// importable.
//
// The format is data, and the client refuses such a package at load time as
// well. Refused here so the catalog never lists one: a package that only fails
// on the installer's machine looks like the installer's problem.
func refuseExecutableEntries(reader *zip.Reader) error {
	suffixes := []string{".py", ".pyc", ".pyo", ".pth", ".so", ".dylib", ".dll"}
	for _, f := range reader.File {
		normalized, err := normalizeEntryName(f.Name)
		if err != nil {
			continue
		}
		lower := strings.ToLower(normalized)
		for _, suffix := range suffixes {
			if strings.HasSuffix(lower, suffix) {
				return fail(
					"%s holds %s, and a connector package runs no code",
					RootConnectorFile, normalized,
				)
			}
		}
	}
	return nil
}
