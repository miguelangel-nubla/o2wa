package o2wa

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// endpointServer serves public endpoints at their paths, plus a page whose template prints the CSRF token.
func endpointServer(t *testing.T, endpoints ...Endpoint) (*httptest.Server, *http.Client, string) {
	t.Helper()
	f := newFakeIssuer(t)
	app := NewServer("client", "secret", f.srv.URL, "https://app/callback")
	page := filepath.Join(t.TempDir(), "page.html")
	os.WriteFile(page, []byte(`<p id="csrf">{{.CSRFToken}}</p><p id="x">{{.GET.x}}</p>`), 0o600)

	mux := http.NewServeMux()
	mux.HandleFunc("/page", app.Handler(Endpoint{Path: "/page", Public: true, Command: []string{"true"}, HTMLFile: page}))
	for _, e := range endpoints {
		mux.HandleFunc(e.Path, app.Handler(e))
	}
	srv := httptest.NewTLSServer(app.SessionMiddleware(mux))
	t.Cleanup(srv.Close)
	client := srv.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.Timeout = 10 * time.Second // a hung command fails the test instead of blocking it

	_, body := get(t, client, srv.URL+"/page")
	m := regexp.MustCompile(`<p id="csrf">([^<]*)</p>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token in the page: %q", body)
	}
	return srv, client, html.UnescapeString(m[1])
}

func run(t *testing.T, client *http.Client, u, token string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if token != "" {
		req.Header.Set("X-CSRF-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func TestPageEscapesRequestValues(t *testing.T) {
	srv, client, _ := endpointServer(t)
	resp, body := get(t, client, srv.URL+"/page?x="+url.QueryEscape(`<script>alert(1)</script>`))
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("GET value not escaped: %q", body)
	}
	if resp.Header.Get("Content-Type") != "text/html; charset=utf-8" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("page headers: %v", resp.Header)
	}
}

func TestPublicCommandWithoutLogin(t *testing.T) {
	srv, client, token := endpointServer(t, Endpoint{Path: "/hello", Public: true, Command: []string{"echo", "hi"}})
	resp, body := run(t, client, srv.URL+"/hello", token, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"text":"hi"`) {
		t.Fatalf("public command: got %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("command output may be cached: %v", resp.Header)
	}
	if resp, _ := run(t, client, srv.URL+"/hello", "wrong", nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("wrong CSRF token: got %d, want 400", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/hello", nil)
	if resp, err := client.Do(req); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("PUT: got %v %v, want 405", resp.StatusCode, err)
	}
}

func TestFormPostWithCSRFField(t *testing.T) {
	srv, client, token := endpointServer(t,
		Endpoint{Path: "/echo", Public: true, Command: []string{"echo", "{{.POST.name}}|{{.POST.csrfToken}}|{{.GET.none}}"}})
	resp, body := run(t, client, srv.URL+"/echo", "", url.Values{"csrfToken": {token}, "name": {"value"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"text":"value|\u003cno value\u003e|\u003cno value\u003e"`) {
		t.Errorf("form post: got %d %q, want the POST value, no token, <no value> for missing ones", resp.StatusCode, body)
	}
	if resp, _ := run(t, client, srv.URL+"/echo", "", url.Values{"csrfToken": {"wrong"}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("form post with a wrong token: got %d, want 400", resp.StatusCode)
	}
}

func TestLongOutputLineStopsTheStream(t *testing.T) {
	// A 3 MB line: over the limit, so stdout stops with an error, nothing of it is shown as a line, and the command
	// still finishes (its output is read to the end) while stderr keeps flowing.
	srv, client, token := endpointServer(t, Endpoint{Path: "/long", Public: true,
		Command: []string{"sh", "-c", `echo before; head -c 3000000 /dev/zero | tr '\0' a; echo; echo after; echo err >&2`}})
	resp, body := run(t, client, srv.URL+"/long", token, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"text":"before"`) ||
		!strings.Contains(body, "stdout line longer than 1048576 bytes") || !strings.Contains(body, `"text":"err"`) {
		t.Errorf("long line: got %d %q", resp.StatusCode, body[:min(len(body), 600)])
	}
	if strings.Contains(body, "aaaa") || strings.Contains(body, `"text":"after"`) {
		t.Errorf("output after the long line was passed on")
	}
}

func TestBinaryOutput(t *testing.T) {
	srv, client, token := endpointServer(t,
		Endpoint{Path: "/file", Public: true, BinaryOutput: true, ContentType: "application/x-test", FileName: "my file.bin",
			Command: []string{"sh", "-c", `head -c 300000 /dev/zero >&2; printf data`}},
		Endpoint{Path: "/fail", Public: true, BinaryOutput: true, Command: []string{"sh", "-c", `echo nope >&2; exit 3`}})

	// 300 KB on stderr would fill the pipe and block the command if nobody read it.
	resp, body := run(t, client, srv.URL+"/file", token, nil)
	if resp.StatusCode != http.StatusOK || body != "data" {
		t.Fatalf("binary output: got %d %q", resp.StatusCode, body)
	}
	if ct, cd := resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"); ct != "application/x-test" ||
		cd != `attachment; filename="my file.bin"` {
		t.Errorf("binary headers: Content-Type %q, Content-Disposition %q", ct, cd)
	}

	resp, body = run(t, client, srv.URL+"/fail", token, nil)
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "exit status 3") {
		t.Errorf("failing binary command: got %d %q, want 500", resp.StatusCode, body)
	}
}
