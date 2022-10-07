package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidSessionID = errors.New("invalid session id")

type NewSessionIDHandlerFunc func(context.Context) string

type options struct {
	cookieName        string
	cookieDomain      string
	cookieExpiration  time.Duration
	cookieSecure      bool
	cookieSameSite    http.SameSite
	secret            string
	hashFunc          func() hash.Hash
	newSessionID      NewSessionIDHandlerFunc
	sessionExpiration time.Duration
}

var defaultOptions = options{
	cookieName:       "SID",
	cookieExpiration: 7 * 24 * time.Hour,
	cookieSecure:     true,
	cookieSameSite:   http.SameSiteLaxMode,
	secret:           "WZJXFaUBOBpAa9hh3YdgybGCJPwONjQc",
	hashFunc:         sha256.New,
	newSessionID: func(_ context.Context) string {
		return newUUID()
	},
	sessionExpiration: 2 * time.Hour,
}

func SetCookieName(name string) Option {
	return func(o *options) {
		o.cookieName = name
	}
}

func SetCookieExpiration(expiration time.Duration) Option {
	return func(o *options) {
		o.cookieExpiration = expiration
	}
}

func SetCookieSecure(secure bool) Option {
	return func(o *options) {
		o.cookieSecure = secure
	}
}

func SetCookieSameSite(sameSite http.SameSite) Option {
	return func(o *options) {
		o.cookieSameSite = sameSite
	}
}

func SetSecret(secret string) Option {
	return func(o *options) {
		o.secret = secret
	}
}

func SetHashFunc(f func() hash.Hash) Option {
	return func(o *options) {
		o.hashFunc = f
	}
}

func SetSessionIDHandler(f NewSessionIDHandlerFunc) Option {
	return func(o *options) {
		o.newSessionID = f
	}
}

func SetSessionExpiration(expiration time.Duration) Option {
	return func(o *options) {
		o.sessionExpiration = expiration
	}
}

type Option func(*options)

func NewManager(opts ...Option) *Manager {
	o := defaultOptions
	for _, opt := range opts {
		opt(&o)
	}
	return &Manager{
		options: &o,
	}
}

type Manager struct {
	options *options
}

func (m *Manager) NewSessionID(ctx context.Context) string {
	return m.options.newSessionID(ctx)
}

func (m *Manager) SessionExpiration() time.Duration {
	return m.options.sessionExpiration
}

func (m *Manager) SetCookie(ctx context.Context, sid string, w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     m.options.cookieName,
		Value:    m.EncodeSessionID(sid),
		Path:     "/",
		HttpOnly: true,
		Secure:   m.isSecure(r),
		Domain:   m.options.cookieDomain,
		SameSite: m.options.cookieSameSite,
	}

	if exp := m.options.cookieExpiration; exp > 0 {
		cookie.MaxAge = int(exp.Seconds())
		cookie.Expires = time.Now().Add(exp)
	}

	http.SetCookie(w, cookie)
	r.AddCookie(cookie)
}

func (m *Manager) SessionIDFromCookie(ctx context.Context, r *http.Request) (string, error) {
	cookie, err := r.Cookie(m.options.cookieName)
	if err != nil {
		return "", err
	}
	return m.DecodeSessionID(cookie.Value)
}

func (m *Manager) DeleteCookie(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	cookie := &http.Cookie{
		Name:     m.options.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.isSecure(r),
		Domain:   m.options.cookieDomain,
		SameSite: m.options.cookieSameSite,
		MaxAge:   -1,
		Expires:  time.Now(),
	}

	http.SetCookie(w, cookie)
}

func (m *Manager) signature(sid string) string {
	h := hmac.New(m.options.hashFunc, []byte(m.options.secret))
	h.Write([]byte(sid))
	return fmt.Sprintf("%X", h.Sum(nil))
}

func (m *Manager) EncodeSessionID(sid string) string {
	b := base64.StdEncoding.EncodeToString([]byte(sid))
	s := fmt.Sprintf("%s.%s", b, m.signature(sid))
	return url.QueryEscape(s)
}

func (m *Manager) isSecure(r *http.Request) bool {
	if !m.options.cookieSecure {
		return false
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if ip.IsLoopback() || ip.IsPrivate() {
		return true
	}
	if r.URL.Scheme != "" {
		return r.URL.Scheme == "https"
	}
	if r.TLS == nil {
		return false
	}
	return true
}

func (m *Manager) DecodeSessionID(value string) (string, error) {
	value, err := url.QueryUnescape(value)
	if err != nil {
		return "", err
	}

	vals := strings.Split(value, ".")
	if len(vals) != 2 {
		return "", ErrInvalidSessionID
	}

	bsid, err := base64.StdEncoding.DecodeString(vals[0])
	if err != nil {
		return "", err
	}
	sid := string(bsid)

	sign := m.signature(sid)
	if sign != vals[1] {
		return "", ErrInvalidSessionID
	}
	return sid, nil
}
