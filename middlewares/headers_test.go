package middlewares

//Middleware tests based on https://github.com/unrolled/secure

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("bar"))
})

func TestNoConfig(t *testing.T) {
	s := NewHeader()

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Body.String(), "bar")
}

func TestCustomResponseHeader(t *testing.T) {
	s := NewHeader(HeaderOptions{
		CustomResponseHeaders: map[string]string{
			"X-Custom-Response-Header": "test_response",
		},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, res.Header().Get("X-Custom-Response-Header"), "test_response")
}

func TestCustomRequestHeader(t *testing.T) {
	s := NewHeader(HeaderOptions{
		CustomRequestHeaders: map[string]string{
			"X-Custom-Request-Header": "test_request",
		},
	})

	res := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/foo", nil)

	s.Handler(myHandler).ServeHTTP(res, req)

	expect(t, res.Code, http.StatusOK)
	expect(t, req.Header.Get("X-Custom-Request-Header"), "test_request")
}

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected [%v] (type %v) - Got [%v] (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}
