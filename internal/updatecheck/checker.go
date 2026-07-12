// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Package updatecheck polls the GitHub releases API for a newer stable
// Arenet release and exposes a thread-safe Status snapshot. It performs
// NO action beyond reporting — Arenet never downloads or executes an
// update itself (the operator updates the binary/image). The checker is
// only ever run when the operator has opted in (see storage.UpdateCheckConfig).
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// defaultReleasesURL is the GitHub "latest stable release" endpoint.
// /releases/latest excludes prereleases by GitHub convention (D6).
const defaultReleasesURL = "https://api.github.com/repos/barto95100/arenet/releases/latest"

// Status is a snapshot of the checker state, safe to copy by value.
type Status struct {
	Current         string    `json:"current"`
	Latest          string    `json:"latest"`
	URL             string    `json:"url"`
	UpdateAvailable bool      `json:"updateAvailable"`
	LastChecked     time.Time `json:"lastChecked"`
	LastError       string    `json:"lastError"`
}

// Checker holds the poll/compare state. Safe for concurrent use.
type Checker struct {
	current     string
	client      *http.Client
	releasesURL string

	mu   sync.Mutex
	etag string
	st   Status
}

// New builds a Checker for the given running version. A nil client gets
// a default with a 10s timeout.
func New(current string, client *http.Client) *Checker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Checker{
		current:     current,
		client:      client,
		releasesURL: defaultReleasesURL,
		st:          Status{Current: current},
	}
}

// Status returns the current snapshot.
func (c *Checker) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

type releaseResp struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// Check performs one poll. Failures never bubble up as an error — they
// land in Status.LastError (D5: a failed check is not an operator
// problem). LastChecked is always refreshed. Returns the new snapshot.
func (c *Checker) Check(ctx context.Context) Status {
	c.mu.Lock()
	etag := c.etag
	st := c.st
	c.mu.Unlock()

	st.LastChecked = time.Now().UTC()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.releasesURL, nil)
	if err != nil {
		st.LastError = err.Error()
		return c.store(st, etag)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		st.LastError = err.Error()
		return c.store(st, etag)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		st.LastError = ""
		return c.store(st, etag) // keep prior Latest/URL/etag
	case http.StatusOK:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var rr releaseResp
		if jerr := json.Unmarshal(body, &rr); jerr != nil {
			st.LastError = fmt.Sprintf("parse release: %v", jerr)
			return c.store(st, etag)
		}
		st.Latest = rr.TagName
		st.URL = rr.HTMLURL
		st.UpdateAvailable = compareSemver(c.current, rr.TagName)
		st.LastError = ""
		return c.store(st, resp.Header.Get("Etag"))
	default:
		st.LastError = fmt.Sprintf("github returned %d", resp.StatusCode)
		return c.store(st, etag)
	}
}

func (c *Checker) store(st Status, etag string) Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.st = st
	c.etag = etag
	return st
}

// compareSemver reports whether latest is strictly newer than current.
// Tolerates a leading "v" and a -pre/+build suffix. A non-semver
// version on either side (e.g. "DEV") never reports an update.
func compareSemver(current, latest string) bool {
	cur, ok1 := parseSemver(current)
	lat, ok2 := parseSemver(latest)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if lat[i] != cur[i] {
			return lat[i] > cur[i]
		}
	}
	return false
}

func parseSemver(v string) ([3]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		// Tolerate a pre-release / build suffix on the patch component
		// (e.g. "3-rc1", "3+build"). Split on the first '-' or '+'.
		fields := strings.FieldsFunc(p, func(r rune) bool { return r == '-' || r == '+' })
		if len(fields) == 0 {
			return [3]int{}, false
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}
