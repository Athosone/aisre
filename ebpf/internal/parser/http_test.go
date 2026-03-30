package parser_test

import (
	"testing"

	"github.com/athosone/aisre/ebpf/internal/parser"
)

func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantMethod string
		wantPath   string
		wantVer    string
		wantErr    bool
	}{
		{
			name:       "simple GET",
			input:      []byte("GET /api/health HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.81\r\n\r\n"),
			wantMethod: "GET",
			wantPath:   "/api/health",
			wantVer:    "HTTP/1.1",
		},
		{
			name:       "POST with body",
			input:      []byte("POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}"),
			wantMethod: "POST",
			wantPath:   "/api/data",
			wantVer:    "HTTP/1.1",
		},
		{
			name:       "DELETE",
			input:      []byte("DELETE /api/items/42 HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			wantMethod: "DELETE",
			wantPath:   "/api/items/42",
			wantVer:    "HTTP/1.1",
		},
		{
			name:       "PUT",
			input:      []byte("PUT /api/items/1 HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			wantMethod: "PUT",
			wantPath:   "/api/items/1",
			wantVer:    "HTTP/1.1",
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "not HTTP",
			input:   []byte("some random data"),
			wantErr: true,
		},
		{
			name:    "truncated request line",
			input:   []byte("GET /ap"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := parser.ParseHTTPRequest(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", req.Method, tt.wantMethod)
			}
			if req.Path != tt.wantPath {
				t.Errorf("Path = %q, want %q", req.Path, tt.wantPath)
			}
			if req.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", req.Version, tt.wantVer)
			}
		})
	}
}

func TestParseHTTPRequestHeaders(t *testing.T) {
	input := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nAccept: application/json\r\n\r\n")
	req, err := parser.ParseHTTPRequest(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should preserve duplicate headers
	acceptCount := 0
	for _, h := range req.Headers {
		if h.Key == "Accept" {
			acceptCount++
		}
	}
	if acceptCount != 2 {
		t.Errorf("expected 2 Accept headers, got %d", acceptCount)
	}
}

func TestParseHTTPRequestBody(t *testing.T) {
	body := `{"hello":"world"}`
	input := []byte("POST /data HTTP/1.1\r\nContent-Length: 17\r\n\r\n" + body)
	req, err := parser.ParseHTTPRequest(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(req.PartialBody) != body {
		t.Errorf("Body = %q, want %q", string(req.PartialBody), body)
	}
}

func TestParseHTTPResponse(t *testing.T) {
	tests := []struct {
		name       string
		input      []byte
		wantStatus uint32
		wantText   string
		wantVer    string
		wantErr    bool
	}{
		{
			name:       "200 OK",
			input:      []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"),
			wantStatus: 200,
			wantText:   "OK",
			wantVer:    "HTTP/1.1",
		},
		{
			name:       "404 Not Found",
			input:      []byte("HTTP/1.1 404 Not Found\r\n\r\n"),
			wantStatus: 404,
			wantText:   "Not Found",
			wantVer:    "HTTP/1.1",
		},
		{
			name:       "201 Created",
			input:      []byte("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{\"id\":1}"),
			wantStatus: 201,
			wantText:   "Created",
			wantVer:    "HTTP/1.1",
		},
		{
			name:    "empty",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "not HTTP response",
			input:   []byte("GET /foo HTTP/1.1\r\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := parser.ParseHTTPResponse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if resp.StatusText != tt.wantText {
				t.Errorf("StatusText = %q, want %q", resp.StatusText, tt.wantText)
			}
			if resp.Version != tt.wantVer {
				t.Errorf("Version = %q, want %q", resp.Version, tt.wantVer)
			}
		})
	}
}

func TestParseHTTPResponseBody(t *testing.T) {
	input := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world")
	resp, err := parser.ParseHTTPResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.PartialBody) != "hello world" {
		t.Errorf("Body = %q, want %q", string(resp.PartialBody), "hello world")
	}
}
