// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
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

// Adapted from
//   github.com/corazawaf/coraza-caddy/v2@v2.5.0/http.go
//   github.com/corazawaf/coraza-caddy/v2@v2.5.0/utils.go
// (Apache-2.0). See interceptor.go header for rationale.

package waf

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3/types"
)

// errInterruptionTriggered is returned via HandlerError when
// Coraza's transaction is interrupted by a rule action (deny,
// drop). The caller in module.go translates it into the
// final HTTP status the client sees.
var errInterruptionTriggered = errors.New("waf rule interruption triggered")

// processRequest runs the request through the Coraza
// transaction phases: connection → URI → request headers →
// optional body. Returns the first interruption observed (or
// nil) and a transport error if Coraza itself failed.
func processRequest(tx types.Transaction, req *http.Request) (*types.Interruption, error) {
	client, cport := getClientAddress(req)

	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(req.URL.String(), req.Method, req.Proto)
	for k, vr := range req.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	// Host header is promoted to req.Host by net/http;
	// re-add it so CRS host-aware rules work.
	if req.Host != "" {
		tx.AddRequestHeader("Host", req.Host)
		tx.SetServerName(parseServerName(req.Host))
	}
	// Transfer-Encoding is also stripped by net/http; re-add
	// to allow CRS rules (e.g. 920171) that detect
	// request-smuggling via TE.TE attacks.
	for _, te := range req.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return it, nil
	}

	if tx.IsRequestBodyAccessible() && req.Body != nil && req.Body != http.NoBody {
		it, _, err := tx.ReadRequestBodyFrom(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to append request body: %w", err)
		}
		if it != nil {
			return it, nil
		}
		// Rebuild req.Body so downstream handlers can still
		// read it. Inline rather than via a helper — the
		// upstream comment explains the Go 1.19 quirk; the
		// pattern works for Go 1.22+ too.
		rbr, err := tx.RequestBodyReader()
		if err != nil {
			return nil, fmt.Errorf("failed to get request body reader: %w", err)
		}
		body := io.MultiReader(rbr, req.Body)
		if rwt, ok := body.(io.WriterTo); ok {
			req.Body = struct {
				io.Reader
				io.WriterTo
				io.Closer
			}{body, rwt, req.Body}
		} else {
			req.Body = struct {
				io.Reader
				io.Closer
			}{body, req.Body}
		}
	}
	return tx.ProcessRequestBody()
}

// getClientAddress resolves the request's effective client IP
// + port, consulting Caddy's `client_ip` request var first
// (which honours the `trusted_proxies` chain) and falling
// back to req.RemoteAddr.
func getClientAddress(req *http.Request) (string, int) {
	if addr, ok := caddyhttp.GetVar(req.Context(), caddyhttp.ClientIPVarKey).(string); ok && addr != "" {
		ip, port, _ := net.SplitHostPort(addr)
		if ip == "" {
			ip = addr
		}
		p, _ := strconv.Atoi(port)
		return ip, p
	}
	idx := strings.LastIndexByte(req.RemoteAddr, ':')
	if idx == -1 {
		return req.RemoteAddr, 0
	}
	port, _ := strconv.Atoi(req.RemoteAddr[idx+1:])
	return req.RemoteAddr[:idx], port
}

// parseServerName extracts the hostname (no port) from the
// request's Host header for the SetServerName call.
func parseServerName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
