// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// openAPIFiles holds the hand-written OpenAPI document (v2.39): base.yaml
// plus one fragment per API domain. See
// docs/superpowers/specs/2026-09-22-openapi-design.md.
//
//go:embed openapi/*.yaml
var openAPIFiles embed.FS

// openAPIBase is the fragment holding info, security and shared
// components; every other file adds paths and schemas.
const openAPIBase = "openapi/base.yaml"

// mergedOpenAPI caches the merged document (the files are embedded, so
// it never changes at runtime).
var mergedOpenAPI = sync.OnceValues(func() (map[string]any, error) { return buildOpenAPI(openAPIFiles) })

// buildOpenAPI merges the base document with every fragment. A path, a
// schema, a response or a parameter defined twice is an error.
func buildOpenAPI(fsys fs.FS) (map[string]any, error) {
	doc, err := readOpenAPIFile(fsys, openAPIBase)
	if err != nil {
		return nil, err
	}
	names, err := fs.Glob(fsys, "openapi/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("openapi: list fragments: %w", err)
	}
	sort.Strings(names)
	paths := childMap(doc, "paths")
	components := childMap(doc, "components")
	for _, name := range names {
		if name == openAPIBase {
			continue
		}
		frag, err := readOpenAPIFile(fsys, name)
		if err != nil {
			return nil, err
		}
		if err := mergeInto(paths, childMap(frag, "paths"), name, "path"); err != nil {
			return nil, err
		}
		fragComponents := childMap(frag, "components")
		for _, kind := range []string{"schemas", "responses", "parameters"} {
			if err := mergeInto(childMap(components, kind), childMap(fragComponents, kind), name, kind); err != nil {
				return nil, err
			}
		}
	}
	addOperationIDs(paths)
	return doc, nil
}

// openAPIMethodOrder lists the HTTP methods an OpenAPI path item holds.
var openAPIMethodOrder = []string{"get", "put", "post", "delete", "patch"}

// addOperationIDs gives every operation without one a stable
// operationId derived from its method and path ("getRoutesById",
// "postRoutesByIdWafTest") — client generators need them.
func addOperationIDs(paths map[string]any) {
	for p, raw := range paths {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for _, m := range openAPIMethodOrder {
			op, ok := item[m].(map[string]any)
			if !ok {
				continue
			}
			if id, _ := op["operationId"].(string); id == "" {
				op["operationId"] = deriveOperationID(m, p)
			}
		}
	}
}

// deriveOperationID builds method + CamelCase path segments, path
// parameters as "By<Name>".
func deriveOperationID(method, path string) string {
	var b strings.Builder
	b.WriteString(method)
	for _, seg := range strings.Split(path, "/") {
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			b.WriteString("By")
			seg = strings.Trim(seg, "{}")
		}
		for _, word := range strings.FieldsFunc(seg, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			b.WriteString(strings.ToUpper(word[:1]) + word[1:])
		}
	}
	return b.String()
}

// readOpenAPIFile decodes one YAML file into JSON-compatible values.
func readOpenAPIFile(fsys fs.FS, name string) (map[string]any, error) {
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("openapi: read %s: %w", name, err)
	}
	var v any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("openapi: parse %s: %w", name, err)
	}
	m, ok := jsonCompatible(v).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("openapi: %s is not a mapping", name)
	}
	return m, nil
}

// jsonCompatible turns YAML maps with non-string keys (status codes
// such as 200) into map[string]any.
func jsonCompatible(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = jsonCompatible(e)
		}
		return t
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[fmt.Sprint(k)] = jsonCompatible(e)
		}
		return out
	case []any:
		for i, e := range t {
			t[i] = jsonCompatible(e)
		}
		return t
	}
	return v
}

// childMap returns m[key] as a map, creating it when absent.
func childMap(m map[string]any, key string) map[string]any {
	if c, ok := m[key].(map[string]any); ok {
		return c
	}
	c := map[string]any{}
	m[key] = c
	return c
}

// mergeInto copies src into dst, refusing keys already present.
func mergeInto(dst, src map[string]any, file, kind string) error {
	for k, v := range src {
		if _, dup := dst[k]; dup {
			return fmt.Errorf("openapi: %s %q defined twice (again in %s)", kind, k, file)
		}
		dst[k] = v
	}
	return nil
}

// openAPIJSON renders the merged document with info.version set to the
// running binary's version.
func openAPIJSON(version string) ([]byte, error) {
	doc, err := mergedOpenAPI()
	if err != nil {
		return nil, err
	}
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		out[k] = v
	}
	info := map[string]any{}
	for k, v := range childMap(doc, "info") {
		info[k] = v
	}
	if version != "" {
		info["version"] = version
	}
	out["info"] = info
	return json.Marshal(out)
}

// getOpenAPI handles GET /api/v1/openapi.json.
func (h *Handler) getOpenAPI(w http.ResponseWriter, _ *http.Request) {
	body, err := openAPIJSON(h.version)
	if err != nil {
		h.logger.Error("openapi document", "err", err)
		writeError(w, http.StatusInternalServerError, "openapi document unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
