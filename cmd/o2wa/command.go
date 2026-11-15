package o2wa

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io"
	"log"
	"mime"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"
)

//go:embed defaultPage.html
var defaultPage string

// maxLine is the longest output line passed on. A longer line stops that output stream with an error on stderr:
// splitting it would show its pieces as separate, complete-looking lines.
const maxLine = 1 << 20

// maxForm limits the body of a command POST, which only carries form values.
const maxForm = 1 << 20

type Endpoint struct {
	Path           string   `json:"path" yaml:"path"`
	Public         bool     `json:"public,omitempty" yaml:"public,omitempty"`
	RequiredGroups []string `json:"requiredGroups,omitempty" yaml:"requiredGroups,omitempty"`
	Command        []string `json:"command" yaml:"command"`
	BinaryOutput   bool     `json:"binaryOutput,omitempty" yaml:"binaryOutput,omitempty"`
	ContentType    string   `json:"contentType,omitempty" yaml:"contentType,omitempty"` // binaryOutput media type
	FileName       string   `json:"fileName,omitempty" yaml:"fileName,omitempty"`       // binaryOutput: download as
	HTMLFile       string   `json:"htmlFile" yaml:"htmlFile"`
	// Timeout ends the command after this long (a Go duration: "60s", "5m"). Empty: the command may run forever.
	Timeout string `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// Validate reports a setting that would only fail later, when the endpoint is used.
func (e Endpoint) Validate() error {
	if _, err := e.timeout(); err != nil {
		return fmt.Errorf("endpoint %s: timeout: %w", e.Path, err)
	}
	return nil
}

func (e Endpoint) timeout() (time.Duration, error) {
	if e.Timeout == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(e.Timeout)
	if err == nil && d <= 0 {
		err = errors.New("must be positive")
	}
	return d, err
}

type templateVariables struct {
	GET                 map[string]string
	POST                map[string]string
	HTTPRequestHeaders  map[string]string
	HTTPResponseHeaders map[string]string
	CSRFToken           string
	AuthClaims          *idTokenClaims // nil on a public endpoint without a login
}

type outputLine struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Text      string    `json:"text"`
}

// Handler serves an endpoint: GET shows its page, POST runs its command. Unless the endpoint is public, both need
// a login with the required groups.
func (app *Server) Handler(e Endpoint) http.HandlerFunc {
	handler := func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			app.HandleCommandConfirm(w, r, e)
		case http.MethodPost:
			app.HandleCommandRun(w, r, e)
		default:
			w.Header().Set("Allow", "GET, HEAD, POST")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
	if e.Public {
		return handler
	}
	return app.AuthMiddleware(e.RequiredGroups, handler)
}

func (app *Server) HandleCommandConfirm(w http.ResponseWriter, r *http.Request, e Endpoint) {
	// html/template: values from the request (GET, headers) or the login end up escaped in the page, not as markup.
	var tmpl *htmltemplate.Template
	var err error
	if e.HTMLFile != "" {
		tmpl, err = htmltemplate.ParseFiles(e.HTMLFile)
	} else {
		tmpl, err = htmltemplate.New("defaultPage").Parse(defaultPage)
	}
	if err != nil {
		log.Printf("%s: page template: %s", e.Path, err)
		http.Error(w, "Failed to load the page", http.StatusInternalServerError)
		return
	}

	var page bytes.Buffer
	if err := tmpl.Execute(&page, app.templateVariables(w, r)); err != nil {
		log.Printf("%s: page template: %s", e.Path, err)
		http.Error(w, "Failed to render the page", http.StatusInternalServerError)
		return
	}
	noStore(w) // the page carries the session's CSRF token
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(page.Bytes())
}

func (app *Server) HandleCommandRun(w http.ResponseWriter, r *http.Request, e Endpoint) {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	if !app.validateCSRFToken(r) {
		http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	err := app.executeCommand(w, r, e)
	if err != nil {
		http.Error(w, "Failed to execute command: "+err.Error(), http.StatusInternalServerError)
		return
	}
}

// noStore keeps command output and pages (secrets, CSRF tokens) out of browser and proxy caches.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

func (app *Server) executeCommand(w http.ResponseWriter, r *http.Request, e Endpoint) error {
	command, err := app.parseCommand(w, r, e)
	if err != nil {
		return err
	}

	user := "anonymous"
	if auth := app.auth(r); auth != nil {
		user = auth.IDTokenClaims.PreferredUsername
	}
	log.Printf("%s requested %s, running: %q", user, e.Path, command) // %q: a value with a newline cannot forge a log line

	cmd := exec.Command(command[0], command[1:]...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	// The timeout is the command's own, not the request's: a client that goes away does not stop a command half
	// way. Past it the command is killed and its pipes closed, so a child that survives cannot hold the request.
	var timedOut atomic.Bool
	if timeout, _ := e.timeout(); timeout > 0 {
		timer := time.AfterFunc(timeout, func() {
			timedOut.Store(true)
			log.Printf("%s: command killed after %s", e.Path, timeout)
			cmd.Process.Kill()
			stdout.Close()
			stderr.Close()
		})
		defer timer.Stop()
	}

	noStore(w)
	if e.BinaryOutput {
		err := app.binaryOutput(w, e, cmd, stdout, stderr)
		if timedOut.Load() {
			return fmt.Errorf("timed out after %s", e.Timeout)
		}
		return err
	}

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	var wg sync.WaitGroup
	var writeMutex sync.Mutex
	writeLine := func(source, text string) {
		jsonLine, _ := json.Marshal(outputLine{Timestamp: time.Now(), Source: source, Text: text})
		writeMutex.Lock()
		defer writeMutex.Unlock()
		w.Write(append(jsonLine, '\n'))
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // stream each line as it comes, for long-running commands
		}
	}
	stream := func(source string, pipe io.Reader) {
		defer wg.Done()
		reader := bufio.NewReaderSize(pipe, maxLine)
		for {
			line, err := reader.ReadSlice('\n')
			if err == bufio.ErrBufferFull {
				writeLine("stderr", fmt.Sprintf("%s line longer than %d bytes: rest of %s dropped", source, maxLine, source))
				io.Copy(io.Discard, reader) // keep reading, or the command blocks on its full pipe and never ends
				return
			}
			if len(line) > 0 {
				writeLine(source, strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"))
			}
			if err != nil {
				return // EOF, or the pipe closed: everything read
			}
		}
	}
	wg.Add(2)
	go stream("stdout", stdout)
	go stream("stderr", stderr)
	wg.Wait() // all output read before Wait, which closes the pipes

	if err := cmd.Wait(); timedOut.Load() {
		writeLine("stderr", "command timed out after "+e.Timeout)
	} else if err != nil {
		writeLine("stderr", err.Error())
	}
	return nil
}

// binaryOutput streams stdout as the response body. stderr is read at the same time (a command that fills the
// stderr pipe would block otherwise) and logged.
func (app *Server) binaryOutput(w http.ResponseWriter, e Endpoint, cmd *exec.Cmd, stdout, stderr io.Reader) error {
	// The download headers are set with the first byte of output: a command that fails without output answers
	// with a plain error, not with a file named fileName that holds the error message.
	out := &lazyHeaders{w: w, set: func() {
		contentType := e.ContentType
		if contentType == "" {
			contentType = "application/octet-stream"
		}
		w.Header().Set("Content-Type", contentType)
		if e.FileName != "" {
			w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": e.FileName}))
		}
	}}

	var stderrBuf bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(&limitedWriter{&stderrBuf, 64 << 10}, stderr)
	}()
	// net/http holds back the first few KB, so a command that fails before writing much still gets an error status.
	_, copyErr := io.Copy(out, stdout)
	if copyErr != nil {
		io.Copy(io.Discard, stdout) // the client is gone: drain, or a command blocked on a full pipe never ends
	}
	<-done
	err := cmd.Wait()
	if stderrBuf.Len() > 0 {
		log.Printf("%s stderr: %s", e.Path, strings.TrimSpace(stderrBuf.String()))
	}
	if err != nil {
		w.Header().Del("Content-Disposition") // no effect once the headers are sent: then the download is cut short
		return err
	}
	if !out.done {
		out.set() // no output at all: an empty file
	}
	return copyErr
}

// lazyHeaders calls set before the first write.
type lazyHeaders struct {
	w    io.Writer
	set  func()
	done bool
}

func (l *lazyHeaders) Write(p []byte) (int, error) {
	if !l.done && len(p) > 0 {
		l.set()
		l.done = true
	}
	return l.w.Write(p)
}

// limitedWriter keeps the first n bytes and discards the rest, so it never blocks or fails the writer.
type limitedWriter struct {
	buf *bytes.Buffer
	n   int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.n - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (app *Server) parseCommand(w http.ResponseWriter, r *http.Request, e Endpoint) ([]string, error) {
	templateVariables := app.templateVariables(w, r)

	parsedCommand := make([]string, len(e.Command))
	for i, v := range e.Command {
		// Keep the default missingkey: a missing GET/POST value becomes the non-empty "<no value>", which a script
		// rejects, never "", which a script may take as "not given, use the default".
		tmpl, err := template.New("command").Parse(v)
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		err = tmpl.Execute(&buf, templateVariables)
		if err != nil {
			return nil, err
		}
		parsedCommand[i] = buf.String()
	}

	return parsedCommand, nil
}

func (app *Server) templateVariables(w http.ResponseWriter, r *http.Request) templateVariables {
	templateVariables := templateVariables{
		CSRFToken: app.csrfToken(r),
	}
	if auth := app.auth(r); auth != nil {
		templateVariables.AuthClaims = &auth.IDTokenClaims
	}

	templateVariables.GET = make(map[string]string)
	for k, v := range r.URL.Query() {
		templateVariables.GET[k] = v[0]
	}

	templateVariables.POST = make(map[string]string)
	for k, v := range r.PostForm {
		if k != csrfFormField {
			templateVariables.POST[k] = v[0]
		}
	}

	templateVariables.HTTPRequestHeaders = make(map[string]string)
	for k, v := range r.Header {
		// Credentials stay out of pages and /values: the session cookie is HttpOnly so that no script can read it.
		if k == "Cookie" || k == "Authorization" || k == "Proxy-Authorization" {
			continue
		}
		templateVariables.HTTPRequestHeaders[k] = v[0]
	}

	templateVariables.HTTPResponseHeaders = make(map[string]string)
	for k, v := range w.Header() {
		templateVariables.HTTPResponseHeaders[k] = v[0]
	}

	return templateVariables
}
