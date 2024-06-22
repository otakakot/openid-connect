package jshttp

import (
	"io"
	"net/http"
	"sync"
	"syscall/js"

	"github.com/syumai/workers/internal/jsutil"
)

type ResponseWriter struct {
	HeaderValue http.Header
	StatusCode  int
	Reader      io.ReadCloser
	Writer      *io.PipeWriter
	ReadyCh     chan struct{}
	Once        sync.Once
	RawJSBody   *js.Value
}

var (
	_ http.ResponseWriter    = (*ResponseWriter)(nil)
	_ jsutil.RawJSBodyWriter = (*ResponseWriter)(nil)
)

// Ready indicates that ResponseWriter is ready to be converted to Response.
func (w *ResponseWriter) Ready() {
	w.Once.Do(func() {
		close(w.ReadyCh)
	})
}

func (w *ResponseWriter) Write(data []byte) (n int, err error) {
	w.Ready()
	return w.Writer.Write(data)
}

func (w *ResponseWriter) Header() http.Header {
	return w.HeaderValue
}

func (w *ResponseWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
}

func (w *ResponseWriter) WriteRawJSBody(body js.Value) {
	w.RawJSBody = &body
}

// ToJSResponse converts *ResponseWriter to JavaScript sides Response.
//   - Response: https://developer.mozilla.org/docs/Web/API/Response
func (w *ResponseWriter) ToJSResponse() js.Value {
	return newJSResponse(w.StatusCode, w.HeaderValue, w.Reader, w.RawJSBody)
}
