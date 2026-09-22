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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func postRaw(env *testEnv, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func putSecLang(env *testEnv, id, secLangJSON string) *httptest.ResponseRecorder {
	body := `{"host":"waf.local","upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
		`"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"block"`
	if secLangJSON != "" {
		body += `,"wafSecLang":` + secLangJSON
	}
	body += `}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

const goodSecLang = `SecRule ARGS:role "@streq admin" "id:130000,phase:2,deny,status:401,msg:'No self-promotion'"`

func TestUpdateRoute_WAFSecLang(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{})

	b, _ := json.Marshal(goodSecLang)
	if rec := putSecLang(env, route.ID, string(b)); rec.Code != http.StatusOK {
		t.Fatalf("PUT: status=%d body=%s", rec.Code, rec.Body)
	}
	stored, _ := env.store.GetRoute(context.Background(), route.ID)
	if stored.WAFSecLang != goodSecLang {
		t.Fatalf("stored = %q", stored.WAFSecLang)
	}
	if rec := putSecLang(env, route.ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("PUT without field: %d", rec.Code)
	}
	if stored, _ = env.store.GetRoute(context.Background(), route.ID); stored.WAFSecLang != goodSecLang {
		t.Fatal("absent field must preserve")
	}

	bad, _ := json.Marshal("SecRule ARGS \"@rx x\" \"id:130000,phase:1,deny\"\nInclude /etc/passwd")
	rec := putSecLang(env, route.ID, string(bad))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Include: status=%d, want 400", rec.Code)
	}
	var e struct {
		Code   string `json:"code"`
		Params struct {
			Errors []struct {
				Line    int    `json:"line"`
				Message string `json:"message"`
			} `json:"errors"`
		} `json:"params"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if e.Code != codeSecLangInvalid || len(e.Params.Errors) != 1 || e.Params.Errors[0].Line != 2 {
		t.Fatalf("error body = %s, want seclang_invalid with line 2", rec.Body)
	}
	if stored, _ = env.store.GetRoute(context.Background(), route.ID); stored.WAFSecLang != goodSecLang {
		t.Fatal("a refused SecLang must not be stored")
	}
	if rec := putSecLang(env, route.ID, `""`); rec.Code != http.StatusOK {
		t.Fatalf("clear: %d", rec.Code)
	}
	if stored, _ = env.store.GetRoute(context.Background(), route.ID); stored.WAFSecLang != "" {
		t.Fatal(`"" must clear`)
	}
}

func TestValidateSecLang_Endpoint(t *testing.T) {
	env := newTestEnv(t, false)
	body, _ := json.Marshal(map[string]string{"seclang": goodSecLang + "\nSecAction \"id:130004,phase:1,pass,nolog\""})
	rec := postRaw(env, "/api/v1/waf/seclang/validate", string(body))
	var resp secLangValidateResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || len(resp.Errors) != 0 || resp.NextID != 130005 {
		t.Fatalf("status=%d resp=%+v, want no error and nextId 130005", rec.Code, resp)
	}
	body, _ = json.Marshal(map[string]string{"seclang": `SecAction "id:130000,phase:1,pass,setenv:X=1"`})
	rec = postRaw(env, "/api/v1/waf/seclang/validate", string(body))
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Errors) != 1 || !strings.Contains(resp.Errors[0].Message, "setenv") {
		t.Fatalf("setenv: %+v", resp)
	}
	rec = postRaw(env, "/api/v1/waf/seclang/validate", `{"seclang":""}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.NextID != 130000 || resp.Errors == nil {
		t.Fatalf("empty: %+v (errors must be [] and nextId 130000)", resp)
	}
}

func TestSecLangFromGuided_Endpoint(t *testing.T) {
	env := newTestEnv(t, false)
	rec := postRaw(env, "/api/v1/waf/seclang/from-guided",
		`{"id":130002,"rule":{"id":120000,"name":"Admin","conditions":[{"field":"path","operator":"begins_with","values":["/admin"]}]}}`)
	var resp map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !strings.Contains(resp["seclang"], "id:130002") || !strings.Contains(resp["seclang"], "msg:'Admin'") {
		t.Fatalf("status=%d resp=%v", rec.Code, resp)
	}
	if rec := postRaw(env, "/api/v1/waf/seclang/from-guided", `{"id":120000,"rule":{"name":"x","conditions":[{"field":"path","operator":"is","values":["/x"]}]}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("id outside the SecLang range: status=%d, want 400", rec.Code)
	}
}

func TestRouteWAFTest_Endpoint(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{WAFSecLang: goodSecLang})

	ua := `[{"name":"User-Agent","value":"Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"},{"name":"Accept","value":"text/html"},` +
		`{"name":"Content-Type","value":"application/x-www-form-urlencoded"}]`
	rec := postRaw(env, "/api/v1/routes/"+route.ID+"/waf-test", `{"method":"POST","path":"/profile","headers":`+ua+`,"body":"role=admin"}`)
	var resp wafTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || !resp.Blocked || resp.BlockedBy != 130000 || resp.Status != 401 || resp.Mode != "block" {
		t.Fatalf("status=%d resp=%+v, want blocked 401 by 130000 in block mode", rec.Code, resp)
	}

	// A draft replaces the stored SecLang.
	draft, _ := json.Marshal(`SecRule ARGS:role "@streq root" "id:130000,phase:2,deny,msg:'root'"`)
	rec = postRaw(env, "/api/v1/routes/"+route.ID+"/waf-test", `{"method":"POST","path":"/profile","headers":`+ua+`,"body":"role=admin","seclang":`+string(draft)+`}`)
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Blocked {
		t.Fatalf("draft: %+v, want accepted", resp)
	}
	bad, _ := json.Marshal(`Include /etc/passwd`)
	if rec := postRaw(env, "/api/v1/routes/"+route.ID+"/waf-test", `{"path":"/","seclang":`+string(bad)+`}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid draft: status=%d, want 400", rec.Code)
	}
	if rec := postRaw(env, "/api/v1/routes/missing/waf-test", `{"path":"/"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown route: %d", rec.Code)
	}
	if env.caddy.CallCount() != 0 {
		t.Fatal("the tester must not reload Caddy")
	}
}

func TestCustomRuleNames_SecLangMsg(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{WAFSecLang: goodSecLang})
	if got := env.handler.newCustomRuleNames().lookup(context.Background(), route.ID, "130000"); got != "No self-promotion" {
		t.Fatalf("lookup = %q, want the msg", got)
	}
}
