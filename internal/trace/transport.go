package trace

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
)

const payloadSizeLimit int64 = 16 * 1024 // 16 KiB

var requestCount uint64

type Transport struct {
	http.RoundTripper

	lastResponse atomic.Pointer[http.Response]
}

func NewTransport(base http.RoundTripper) *Transport {
	return &Transport{RoundTripper: base}
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	id := atomic.AddUint64(&requestCount, 1) - 1
	ctx := req.Context()
	logger := Logger(ctx)

	// log the request
	logger.Debugf("📤 Request #%d\n%s %s\n%s\n", id, req.Method, req.URL, logHeader(req.Header))

	// log the response
	resp, err := t.RoundTripper.RoundTrip(req)
	if err != nil {
		logger.Errorf("Response #%d\nError: %v", id, err)
	} else if resp == nil {
		logger.Errorf("Response #%d\nMissing response", id)
	} else {
		logger.Debugf("📥 Response #%d\n%s\n%s\n\n%s", id, resp.Status, logHeader(resp.Header), logResponseBody(resp))
	}

	// store the last response
	t.lastResponse.Store(resp)

	return resp, err
}

func (t *Transport) LastResponse() *http.Response {
	return t.lastResponse.Load()
}

func logHeader(header http.Header) string {
	if len(header) == 0 {
		return ""
	}

	headers := make([]string, 0, len(header))
	for k, v := range header {
		if k == "Authorization" {
			v = []string{"<redacted>"}
		}
		headers = append(headers, fmt.Sprintf("%s: %s", k, strings.Join(v, ", ")))
	}
	return strings.Join(headers, "\n")
}

func logResponseBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}

	buf := bytes.NewBuffer(nil)
	body := resp.Body
	resp.Body = struct {
		io.Reader
		io.Closer
	}{
		Reader: io.MultiReader(buf, body),
		Closer: body,
	}
	if _, err := io.CopyN(buf, body, payloadSizeLimit+1); err != nil && err != io.EOF {
		return fmt.Sprintf("❌ Error reading response body: %v", err)
	}

	readBody := buf.String()
	if strings.Contains(readBody, `"token"`) || strings.Contains(readBody, `"access_token"`) {
		return "<redacted>"
	}
	if len(readBody) > int(payloadSizeLimit) {
		return readBody[:payloadSizeLimit] + "\n...<truncated>"
	}

	return readBody
}
