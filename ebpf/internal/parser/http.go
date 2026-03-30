package parser

import (
	"bytes"
	"fmt"
	"strconv"
)

// Header represents a single HTTP header key-value pair.
type Header struct {
	Key   string
	Value string
}

// HTTPRequestParsed is the result of parsing raw HTTP request bytes.
type HTTPRequestParsed struct {
	Method      string
	Path        string
	Version     string
	Headers     []Header
	PartialBody []byte
}

// HTTPResponseParsed is the result of parsing raw HTTP response bytes.
type HTTPResponseParsed struct {
	StatusCode  uint32
	StatusText  string
	Version     string
	Headers     []Header
	PartialBody []byte
}

var crlf = []byte("\r\n")
var doubleCRLF = []byte("\r\n\r\n")

// ParseHTTPRequest parses raw bytes into a structured HTTP request.
// Only parses the first segment — does not handle multi-read reassembly.
func ParseHTTPRequest(data []byte) (*HTTPRequestParsed, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// Find end of request line
	lineEnd := bytes.Index(data, crlf)
	if lineEnd < 0 {
		return nil, fmt.Errorf("no CRLF found in request line")
	}

	// Parse "METHOD PATH VERSION"
	parts := bytes.SplitN(data[:lineEnd], []byte(" "), 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed request line: %q", string(data[:lineEnd]))
	}

	method := string(parts[0])
	if !isValidMethod(method) {
		return nil, fmt.Errorf("invalid HTTP method: %q", method)
	}

	req := &HTTPRequestParsed{
		Method:  method,
		Path:    string(parts[1]),
		Version: string(parts[2]),
	}

	// Parse headers
	headerStart := lineEnd + 2 // skip \r\n
	headers, bodyStart, err := parseHeaders(data[headerStart:])
	if err != nil {
		return req, nil // Return what we have without headers
	}
	req.Headers = headers

	// Extract body (everything after \r\n\r\n)
	absBodyStart := headerStart + bodyStart
	if absBodyStart < len(data) {
		req.PartialBody = data[absBodyStart:]
	}

	return req, nil
}

// ParseHTTPResponse parses raw bytes into a structured HTTP response.
func ParseHTTPResponse(data []byte) (*HTTPResponseParsed, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	// Must start with "HTTP/"
	if len(data) < 5 || string(data[:5]) != "HTTP/" {
		return nil, fmt.Errorf("not an HTTP response")
	}

	lineEnd := bytes.Index(data, crlf)
	if lineEnd < 0 {
		return nil, fmt.Errorf("no CRLF found in status line")
	}

	statusLine := data[:lineEnd]

	// Split into version, status code, status text
	firstSpace := bytes.IndexByte(statusLine, ' ')
	if firstSpace < 0 {
		return nil, fmt.Errorf("malformed status line")
	}

	version := string(statusLine[:firstSpace])
	rest := statusLine[firstSpace+1:]

	secondSpace := bytes.IndexByte(rest, ' ')
	var codeStr, statusText string
	if secondSpace < 0 {
		codeStr = string(rest)
		statusText = ""
	} else {
		codeStr = string(rest[:secondSpace])
		statusText = string(rest[secondSpace+1:])
	}

	code, err := strconv.ParseUint(codeStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid status code: %q", codeStr)
	}

	resp := &HTTPResponseParsed{
		StatusCode: uint32(code),
		StatusText: statusText,
		Version:    version,
	}

	// Parse headers
	headerStart := lineEnd + 2
	headers, bodyStart, err := parseHeaders(data[headerStart:])
	if err != nil {
		return resp, nil
	}
	resp.Headers = headers

	absBodyStart := headerStart + bodyStart
	if absBodyStart < len(data) {
		resp.PartialBody = data[absBodyStart:]
	}

	return resp, nil
}

// parseHeaders parses HTTP headers from data starting after the request/status line.
// Returns the parsed headers and the offset where the body starts (after \r\n\r\n).
func parseHeaders(data []byte) ([]Header, int, error) {
	var headers []Header

	bodyMarker := bytes.Index(data, doubleCRLF)
	var headerBlock []byte
	var bodyStart int

	if bodyMarker >= 0 {
		headerBlock = data[:bodyMarker]
		bodyStart = bodyMarker + 4 // skip \r\n\r\n
	} else {
		// No body marker — parse what we have
		headerBlock = data
		bodyStart = len(data)
	}

	lines := bytes.Split(headerBlock, crlf)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx < 0 {
			continue // skip malformed header lines
		}
		key := string(line[:colonIdx])
		value := string(bytes.TrimLeft(line[colonIdx+1:], " "))
		headers = append(headers, Header{Key: key, Value: value})
	}

	return headers, bodyStart, nil
}

func isValidMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT":
		return true
	}
	return false
}
