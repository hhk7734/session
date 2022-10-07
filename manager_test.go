package session_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hhk7734/session"
	"github.com/stretchr/testify/assert"
)

func TestSetCookieName(t *testing.T) {
	manager := session.NewManager(session.SetCookieName("test_session"))

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sid := manager.NewSessionID(r.Context())
			manager.SetCookie(r.Context(), sid, w, r)
		},
	))
	defer server.Close()

	res, err := http.Get(server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(res.Cookies()))

	cookie := res.Cookies()[0]
	assert.Equal(t, "test_session", cookie.Name)
}

func TestSetCookie(t *testing.T) {
	manager := session.NewManager(session.SetCookieName("test_session"))

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			manager.SetCookie(r.Context(), "test", w, r)
		},
	))
	defer server.Close()

	res, err := http.Get(server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(res.Cookies()))

	cookie := res.Cookies()[0]
	sid, err := manager.DecodeSessionID(cookie.Value)
	assert.NoError(t, err)
	assert.Equal(t, "test", sid)
}

func TestSessionIDFromCookie(t *testing.T) {
	manager := session.NewManager(session.SetCookieName("test_session"))

	cookie := &http.Cookie{
		Name:  "test_session",
		Value: manager.EncodeSessionID("test"),
	}

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sid, err := manager.SessionIDFromCookie(r.Context(), r)
			assert.NoError(t, err)
			assert.Equal(t, "test", sid)
		},
	))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	assert.NoError(t, err)

	req.AddCookie(cookie)
	_, err = http.DefaultClient.Do(req)
	assert.NoError(t, err)
}

func TestShouldOnlyUpdateExpirationWhenCallingSetCookieWithoutChangingSessionID(t *testing.T) {
	// Given
	manager := session.NewManager(session.SetCookieName("test_session"))
	expire := time.Now().Add(time.Hour)
	reqCookie := &http.Cookie{
		Name:    "test_session",
		Value:   manager.EncodeSessionID("test"),
		Expires: expire,
	}

	// When
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sessionID, err := manager.SessionIDFromCookie(r.Context(), r)
			assert.NoError(t, err)
			manager.SetCookie(r.Context(), sessionID, w, r)
		},
	))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	assert.NoError(t, err)

	req.AddCookie(reqCookie)
	res, err := http.DefaultClient.Do(req)

	// Then
	assert.NoError(t, err)
	assert.Equal(t, 1, len(res.Cookies()))
	resCookie := res.Cookies()[0]
	assert.True(t, resCookie.Expires.After(expire))
}

func TestDeleteCookie(t *testing.T) {
	manager := session.NewManager(session.SetCookieName("test_session"))

	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			manager.DeleteCookie(r.Context(), w, r)
		},
	))
	defer server.Close()

	res, err := http.Get(server.URL)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(res.Cookies()))

	cookie := res.Cookies()[0]
	assert.Equal(t, "test_session", cookie.Name)
	assert.Equal(t, -1, cookie.MaxAge)
	assert.True(t, cookie.Expires.Before(time.Now()))
}
