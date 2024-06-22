package jshttp

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall/js"

	"github.com/syumai/workers/internal/jsutil"
)

// ToBody converts JavaScript sides ReadableStream (can be null) to io.ReadCloser.
//   - ReadableStream: https://developer.mozilla.org/en-US/docs/Web/API/ReadableStream
func ToBody(streamOrNull js.Value) io.ReadCloser {
	if streamOrNull.IsNull() {
		return nil
	}
	return jsutil.ConvertReadableStreamToReadCloser(streamOrNull)
}

// ToRequest converts JavaScript sides Request to *http.Request.
//   - Request: https://developer.mozilla.org/docs/Web/API/Request
func ToRequest(req js.Value) (*http.Request, error) {
	reqUrl, err := url.Parse(req.Get("url").String())
	if err != nil {
		return nil, err
	}
	header := ToHeader(req.Get("headers"))

	// ignore err
	contentLength, _ := strconv.ParseInt(header.Get("Content-Length"), 10, 64)
	return &http.Request{
		Method:           req.Get("method").String(),
		URL:              reqUrl,
		Header:           header,
		Body:             ToBody(req.Get("body")),
		ContentLength:    contentLength,
		TransferEncoding: strings.Split(header.Get("Transfer-Encoding"), ","),
		Host:             header.Get("Host"),
	}, nil
}

// ToJSRequest converts *http.Request to JavaScript sides Request.
//   - Request: https://developer.mozilla.org/docs/Web/API/Request
func ToJSRequest(req *http.Request) js.Value {
	jsReqOptions := jsutil.NewObject()
	jsReqOptions.Set("method", req.Method)
	jsReqOptions.Set("headers", ToJSHeader(req.Header))
	jsReqBody := js.Undefined()
	if req.Body != nil {
		jsReqBody = jsutil.ConvertReaderToReadableStream(req.Body)
	}
	jsReqOptions.Set("body", jsReqBody)
	jsReq := jsutil.RequestClass.New(req.URL.String(), jsReqOptions)
	return jsReq
}
