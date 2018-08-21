package middlewares

// Middleware based on https://github.com/unrolled/secure

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/types"
)

// HeaderOptions is a struct for specifying configuration options for the headers middleware.
type HeaderOptions struct {
	// If Custom request headers are set, these will be added to the request
	CustomRequestHeaders map[string]string
	// If Custom response headers are set, these will be added to the ResponseWriter
	CustomResponseHeaders map[string]string

	// AccessControlAllowCredentials is only valid if true. false is ignored.
	AccessControlAllowCredentials bool
	// AccessControlAllowHeaders must be used in response to a preflight request with Access-Control-Request-Headers set.
	AccessControlAllowHeaders []string
	// AccessControlAllowMethods must be used in response to a preflight request with Access-Control-Request-Method set.
	AccessControlAllowMethods []string
	// AccessControlAllowOrigin Can be "origin-list-or-null" or "*". From (https://www.w3.org/TR/cors/#access-control-allow-origin-response-header)
	AccessControlAllowOrigin string
	// AccessControlExposeHeaders sets valid headers for the response.
	AccessControlExposeHeaders []string
	// AccessControlMaxAge sets the time that a preflight request may be cached.
	AccessControlMaxAge int64
}

// HeaderStruct is a middleware that helps setup a few basic security features. A single headerOptions struct can be
// provided to configure which features should be enabled, and the ability to override a few of the default values.
type HeaderStruct struct {
	// Customize headers with a headerOptions struct.
	opt          HeaderOptions
	originHeader string
}

// NewHeaderFromStruct constructs a new header instance from supplied frontend header struct.
func NewHeaderFromStruct(headers *types.Headers) *HeaderStruct {
	if headers == nil || (!headers.HasCustomHeadersDefined() && !headers.HasCorsHeadersDefined()) {
		return nil
	}

	return &HeaderStruct{
		opt: HeaderOptions{
			CustomRequestHeaders:          headers.CustomRequestHeaders,
			CustomResponseHeaders:         headers.CustomResponseHeaders,
			AccessControlAllowCredentials: headers.AccessControlAllowCredentials,
			AccessControlAllowHeaders:     headers.AccessControlAllowHeaders,
			AccessControlAllowMethods:     headers.AccessControlAllowMethods,
			AccessControlAllowOrigin:      headers.AccessControlAllowOrigin,
			AccessControlExposeHeaders:    headers.AccessControlExposeHeaders,
			AccessControlMaxAge:           headers.AccessControlMaxAge,
		},
	}
}

func (s *HeaderStruct) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	reqAcMethod := r.Header.Get("Access-Control-Request-Method")
	reqAcHeaders := r.Header.Get("Access-Control-Request-Headers")
	s.originHeader = r.Header.Get("Origin")

	if reqAcMethod != "" && reqAcHeaders != "" && s.originHeader != "" && r.Method == http.MethodOptions {
		// Preflight request, build response
		if s.opt.AccessControlAllowCredentials {
			w.Header().Add("Access-Control-Allow-Credentials", "true")
		}

		allowHeaders := strings.Join(s.opt.AccessControlAllowHeaders, ",")
		if allowHeaders != "" {
			w.Header().Add("Access-Control-Allow-Headers", allowHeaders)
		}

		allowMethods := strings.Join(s.opt.AccessControlAllowMethods, ",")
		if allowMethods != "" {
			w.Header().Add("Access-Control-Allow-Methods", allowMethods)
		}

		allowOrigin, err := s.getAllowOrigin()
		if err != nil {
			log.Debugf("Preflight error with Access-Control-Allow-Origin: %v", err)
		}

		if allowOrigin != "" {
			w.Header().Add("Access-Control-Allow-Origin", allowOrigin)
		}

		w.Header().Add("Access-Control-Max-Age", strconv.Itoa(int(s.opt.AccessControlMaxAge)))
	} else {
		s.ModifyRequestHeaders(r)
		// If there is a next, call it.
		if next != nil {
			next(w, r)
		}
	}
}

// ModifyRequestHeaders set or delete request headers
func (s *HeaderStruct) ModifyRequestHeaders(r *http.Request) {
	// Loop through Custom request headers
	for header, value := range s.opt.CustomRequestHeaders {
		if value == "" {
			r.Header.Del(header)
		} else {
			r.Header.Set(header, value)
		}
	}
}

// ModifyResponseHeaders set or delete response headers
func (s *HeaderStruct) ModifyResponseHeaders(res *http.Response) error {
	// Loop through Custom response headers
	for header, value := range s.opt.CustomResponseHeaders {
		if value == "" {
			res.Header.Del(header)
		} else {
			res.Header.Set(header, value)
		}
	}

	allowOrigin, err := s.getAllowOrigin()
	if err != nil {
		return err
	}

	if allowOrigin != "" {
		res.Header.Set("Access-Control-Allow-Origin", allowOrigin)
	}

	if s.opt.AccessControlAllowCredentials {
		res.Header.Set("Access-Control-Allow-Credentials", "true")
	}

	exposeHeaders := strings.Join(s.opt.AccessControlExposeHeaders, ",")
	if exposeHeaders != "" {
		res.Header.Set("Access-Control-Expose-Headers", exposeHeaders)
	}

	return nil
}

func (s *HeaderStruct) getAllowOrigin() (string, error) {
	switch s.opt.AccessControlAllowOrigin {
	case "origin-list-or-null":
		if s.originHeader == "" {
			return "null", nil
		}
		return s.originHeader, nil
	case "*":
		return "*", nil
	}
	return "", fmt.Errorf("invalid Access-Control-Allow-Origin setting: %s", s.opt.AccessControlAllowOrigin)
}
