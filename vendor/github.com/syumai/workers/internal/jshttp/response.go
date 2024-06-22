package jshttp

import (
	"io"
	"net/http"
	"strconv"
	"syscall/js"

	"github.com/syumai/workers/internal/jsutil"
)

func toResponse(res js.Value, body io.ReadCloser) (*http.Response, error) {
	status := res.Get("status").Int()
	header := ToHeader(res.Get("headers"))
	contentLength, _ := strconv.ParseInt(header.Get("Content-Length"), 10, 64)

	return &http.Response{
		Status:        strconv.Itoa(status) + " " + res.Get("statusText").String(),
		StatusCode:    status,
		Header:        header,
		Body:          body,
		ContentLength: contentLength,
	}, nil
}

// ToResponse converts JavaScript sides Response to *http.Response.
//   - Response: https://developer.mozilla.org/docs/Web/API/Response
func ToResponse(res js.Value) (*http.Response, error) {
	body := jsutil.ConvertReadableStreamToReadCloser(res.Get("body"))
	return toResponse(res, body)
}

// ToStreamResponse pipes JavaScript sides Response to TransformStream and converts to *http.Response.
//   - see: https://developers.cloudflare.com/workers/runtime-apis/streams/
func ToStreamResponse(res js.Value) (*http.Response, error) {
	ts := js.Global().Get("IdentityTransformStream").New()
	readable := ts.Get("readable")
	writable := ts.Get("writable")
	res.Get("body").Call("pipeTo", writable)
	body := jsutil.ConvertReadableStreamToReadCloser(readable)
	return toResponse(res, body)
}

// ToJSResponse converts *http.Response to JavaScript sides Response class object.
func ToJSResponse(res *http.Response) js.Value {
	return newJSResponse(res.StatusCode, res.Header, res.Body, nil)
}

// newJSResponse creates JavaScript sides Response class object.
//   - Response: https://developer.mozilla.org/docs/Web/API/Response
func newJSResponse(statusCode int, headers http.Header, body io.ReadCloser, rawBody *js.Value) js.Value {
	status := statusCode
	if status == 0 {
		status = http.StatusOK
	}
	respInit := jsutil.NewObject()
	respInit.Set("status", status)
	respInit.Set("statusText", http.StatusText(status))
	respInit.Set("headers", ToJSHeader(headers))
	if status == http.StatusSwitchingProtocols ||
		status == http.StatusNoContent ||
		status == http.StatusResetContent ||
		status == http.StatusNotModified {
		return jsutil.ResponseClass.New(jsutil.Null, respInit)
	}
	var readableStream js.Value
	if rawBody != nil {
		readableStream = *rawBody
	} else {
		readableStream = jsutil.ConvertReaderToReadableStream(body)
	}
	return jsutil.ResponseClass.New(readableStream, respInit)
}
