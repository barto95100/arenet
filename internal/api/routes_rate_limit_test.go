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

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Step Q (2026-06-18) — API wire layer for Route.RateLimit.
//
// Same shape as the Phase 4.5 UploadStreamingMode + Step X.1
// WAFDisableCRS tests : pointer-typed request field with
// preserve-on-nil semantics ; response always echoes the
// stored value (or nil when no rate limit configured).

func jsonBodyWithRateLimit(host, rateLimitJSON string) string {
	tail := ""
	if rateLimitJSON != "" {
		tail = `,"rateLimit":` + rateLimitJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

func TestCreateRoute_RateLimit_Wire_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithRateLimit("limited.local",
		`{"events":60,"window":"1m","key":"{http.request.remote.host}"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.RateLimit == nil {
		t.Fatalf("response RateLimit = nil ; want non-nil (POST shipped non-nil)")
	}
	if resp.RateLimit.Events != 60 || resp.RateLimit.Window != "1m" {
		t.Errorf("response RateLimit = %+v ; want {Events:60, Window:1m}", resp.RateLimit)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if got[0].RateLimit == nil || got[0].RateLimit.Events != 60 {
		t.Errorf("storage RateLimit = %+v ; want {Events:60}", got[0].RateLimit)
	}
}

func TestCreateRoute_RateLimit_Omitted_DefaultsNil(t *testing.T) {
	// Pre-Q byte-equivalence : a POST without rateLimit
	// persists nil. Caddymgr's emit skips the rate_limit
	// handler entirely for such routes ; the chain shape is
	// byte-equal to pre-Q.
	env := newTestEnv(t, false)
	body := jsonBodyWithRateLimit("default.local", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].RateLimit != nil {
		t.Errorf("storage RateLimit = %+v ; want nil (pre-Q byte-equivalent)",
			got[0].RateLimit)
	}
}

func TestCreateRoute_RateLimit_RejectsInvalid(t *testing.T) {
	env := newTestEnv(t, false)
	cases := []struct {
		name string
		body string
	}{
		{"events_zero", `{"events":0,"window":"1m"}`},
		{"events_negative", `{"events":-1,"window":"1m"}`},
		{"window_empty", `{"events":10,"window":""}`},
		{"window_invalid", `{"events":10,"window":"not-a-duration"}`},
		{"window_zero", `{"events":10,"window":"0s"}`},
		{"window_negative", `{"events":10,"window":"-1m"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := jsonBodyWithRateLimit("bad.local", tc.body)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/routes",
				strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status=%d body=%s ; want 400 for %s",
					rec.Code, rec.Body, tc.name)
			}
		})
	}
}

func TestUpdateRoute_RateLimit_NilPreservesPrevious(t *testing.T) {
	// PUT without the rateLimit key MUST preserve the
	// stored rate limit. Mirror of the WAFDisableCRS PUT
	// preserve-on-omit pattern.
	env := newTestEnv(t, false)

	createBody := jsonBodyWithRateLimit("preserve.local",
		`{"events":42,"window":"2m"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes",
		strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// PUT WITHOUT the rateLimit key.
	putBody := jsonBodyWithRateLimit("preserve.local", "")
	putReq := httptest.NewRequest(http.MethodPut,
		"/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].RateLimit == nil || got[0].RateLimit.Events != 42 {
		t.Errorf("RateLimit lost after PUT-without-key ; got=%+v want={Events:42}",
			got[0].RateLimit)
	}
}

func TestUpdateRoute_RateLimit_NonNilReplaces(t *testing.T) {
	// PUT with explicit rateLimit object replaces the stored
	// value. Operator can tighten or loosen the limit
	// without recreating the route.
	env := newTestEnv(t, false)

	createBody := jsonBodyWithRateLimit("replace.local",
		`{"events":42,"window":"2m"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes",
		strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	putBody := jsonBodyWithRateLimit("replace.local",
		`{"events":100,"window":"5m","key":"{http.request.header.X-Forwarded-For}"}`)
	putReq := httptest.NewRequest(http.MethodPut,
		"/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].RateLimit == nil ||
		got[0].RateLimit.Events != 100 ||
		got[0].RateLimit.Window != "5m" ||
		got[0].RateLimit.Key != "{http.request.header.X-Forwarded-For}" {
		t.Errorf("RateLimit not replaced ; got=%+v", got[0].RateLimit)
	}
}
