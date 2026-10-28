package controller

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// hanPattern 用于断言英文响应里不残留中文
var hanPattern = regexp.MustCompile(`\p{Han}`)

// doLang 发一次请求并返回状态码与响应体；lang 为空表示不带 Accept-Language（默认中文）
func doLang(t *testing.T, srv *httptest.Server, method, path, lang string, body interface{}, token string) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化请求失败: %v", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if lang != "" {
		req.Header.Set("Accept-Language", lang)
	}
	if token != "" {
		req.Header.Set("X-EGP-Token", token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

// apiError 取出 {"error": "..."}
func apiError(t *testing.T, raw string) string {
	t.Helper()
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("响应不是 JSON: %v（%s）", err, raw)
	}
	return payload.Error
}

// TestErrorLanguageFollowsAcceptLanguage 校验同一个错误按 Accept-Language 返回中/英文，
// 且英文里不含任何汉字（包括被嵌套的 config / policymodel 校验文案）。
func TestErrorLanguageFollowsAcceptLanguage(t *testing.T) {
	srv, _ := newTestServer(t, "")

	cases := []struct {
		name   string
		method string
		path   string
		body   interface{}
		wantEn string
	}{
		{
			name:   "非法执行模式",
			method: http.MethodPost,
			path:   "/api/v1/mode",
			body:   map[string]string{"mode": "nope"},
			wantEn: "invalid mode",
		},
		{
			name:   "授权缺少 payload",
			method: http.MethodPost,
			path:   "/api/v1/grant",
			body:   map[string]interface{}{"payload": "", "target": "a.example.com:443", "allowed": true},
			wantEn: "payload and target must not be empty",
		},
		{
			name:   "策略里 host 非法",
			method: http.MethodPut,
			path:   "/api/v1/policy",
			body: map[string]interface{}{
				"generation": 0,
				"mode":       "enforce",
				"payloads": []map[string]interface{}{{
					"name":        "order-svc",
					"namespaces":  []string{"prod-shop"},
					"matchLabels": map[string]string{"app": "order-svc"},
				}},
				"targets": []map[string]interface{}{{"host": "bad_host!", "port": 443, "proxyPort": 20001}},
				"grants":  []interface{}{},
			},
			wantEn: "is invalid",
		},
	}

	for _, c := range cases {
		zhStatus, zhRaw := doLang(t, srv, c.method, c.path, "", c.body, "")
		enStatus, enRaw := doLang(t, srv, c.method, c.path, "en-US,en;q=0.9", c.body, "")
		if zhStatus != enStatus {
			t.Errorf("%s: 状态码不一致 zh=%d en=%d", c.name, zhStatus, enStatus)
		}
		if zhStatus < 400 {
			t.Errorf("%s: 期望失败状态码，实际 %d", c.name, zhStatus)
		}
		zhMsg := apiError(t, zhRaw)
		enMsg := apiError(t, enRaw)
		if !hanPattern.MatchString(zhMsg) {
			t.Errorf("%s: 默认（中文）响应应是中文，实际 %q", c.name, zhMsg)
		}
		if hanPattern.MatchString(enMsg) {
			t.Errorf("%s: 英文响应里残留中文: %q", c.name, enMsg)
		}
		if !strings.Contains(strings.ToLower(enMsg), strings.ToLower(c.wantEn)) {
			t.Errorf("%s: 英文响应缺少 %q，实际 %q", c.name, c.wantEn, enMsg)
		}
	}
}

// TestConflictAndAuthMessageEnglish 覆盖 409 冲突与 401 未授权两条文案
func TestConflictAndAuthMessageEnglish(t *testing.T) {
	srv, _ := newTestServer(t, "")

	// 先写入一版策略，制造 generation 前进
	if status, raw := doLang(t, srv, http.MethodPut, "/api/v1/policy", "", validRequest(0), ""); status != http.StatusOK {
		t.Fatalf("初始策略写入失败 %d: %s", status, raw)
	}
	// 用过期 generation 再写一次 → 409
	status, raw := doLang(t, srv, http.MethodPut, "/api/v1/policy", "en", validRequest(99), "")
	if status != http.StatusConflict {
		t.Fatalf("期望 409，实际 %d: %s", status, raw)
	}
	msg := apiError(t, raw)
	if hanPattern.MatchString(msg) || !strings.Contains(msg, "current generation") {
		t.Errorf("冲突文案英文不正确: %q", msg)
	}

	// 令牌校验：未带令牌时 401 文案也要英文
	authSrv, _ := newTestServer(t, "s3cr3t")
	status, raw = doLang(t, authSrv, http.MethodGet, "/api/v1/state", "en-GB", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际 %d: %s", status, raw)
	}
	if msg := apiError(t, raw); hanPattern.MatchString(msg) || !strings.Contains(msg, "access token") {
		t.Errorf("未授权文案英文不正确: %q", msg)
	}
}

// TestStateWarningsEnglish 覆盖 /api/v1/state 里的 warnings（policymodel 生成的提示）
func TestStateWarningsEnglish(t *testing.T) {
	srv, _ := newTestServer(t, "")
	if status, raw := doLang(t, srv, http.MethodPut, "/api/v1/policy", "", validRequest(0), ""); status != http.StatusOK {
		t.Fatalf("策略写入失败 %d: %s", status, raw)
	}

	status, raw := doLang(t, srv, http.MethodGet, "/api/v1/state", "en", nil, "")
	if status != http.StatusOK {
		t.Fatalf("读取状态失败 %d: %s", status, raw)
	}
	var state struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		t.Fatalf("解析状态失败: %v", err)
	}
	if len(state.Warnings) == 0 {
		t.Fatalf("期望至少一条告警，实际 %v", state.Warnings)
	}
	for _, w := range state.Warnings {
		if hanPattern.MatchString(w) {
			t.Errorf("英文请求下告警里残留中文: %q", w)
		}
	}
	joined := strings.Join(state.Warnings, " | ")
	if !strings.Contains(joined, "has no grant") {
		t.Errorf("告警英文文案不符合预期: %q", joined)
	}

	// 同一份状态，中文请求下应是中文告警
	_, zhRaw := doLang(t, srv, http.MethodGet, "/api/v1/state", "zh-CN", nil, "")
	if err := json.Unmarshal([]byte(zhRaw), &state); err != nil {
		t.Fatalf("解析中文状态失败: %v", err)
	}
	if !hanPattern.MatchString(strings.Join(state.Warnings, " | ")) {
		t.Errorf("中文请求下的告警应是中文: %v", state.Warnings)
	}
}
