package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/benjaminbear/docker-ddns-server/dyndns/handler"
	"github.com/gin-gonic/gin"
)

func newTestRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// InitDB writes to the relative path "database/ddns.db", so run it from a temp dir.
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})

	h := &handler.Handler{}
	if err := h.InitDB(); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	return setupRouter(h, true)
}

func TestPingReturnsOKPayload(t *testing.T) {
	// Given a router with admin auth enabled
	router := newTestRouter(t)

	// When the health-check endpoint is called
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ping", nil))

	// Then it answers 200 with the OK message
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != `{"message":"OK"}` {
		t.Fatalf("body = %q, want %q", got, `{"message":"OK"}`)
	}
}

func TestRootRedirectsToAdmin(t *testing.T) {
	// Given a router with admin auth enabled
	router := newTestRouter(t)

	// When the root path is requested
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	// Then it permanently redirects to the admin UI
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMovedPermanently)
	}
	if got := rec.Header().Get("Location"); got != "./admin/" {
		t.Fatalf("Location = %q, want %q", got, "./admin/")
	}
}

func TestUnknownPathRedirectsToAdmin(t *testing.T) {
	// Given a router with admin auth enabled
	router := newTestRouter(t)

	// When an unregistered path is requested
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/does-not-exist", nil))

	// Then it permanently redirects to the admin UI
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMovedPermanently)
	}
	if got := rec.Header().Get("Location"); got != "./admin/" {
		t.Fatalf("Location = %q, want %q", got, "./admin/")
	}
}

func TestProtectedRoutesChallengeWithoutCredentials(t *testing.T) {
	// Given a router with admin auth enabled
	router := newTestRouter(t)

	for _, path := range []string{"/admin/", "/update"} {
		// When a guarded path is requested without an Authorization header
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

		// Then it answers 401 with a basic auth challenge
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want %d", path, rec.Code, http.StatusUnauthorized)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != `Basic realm="Restricted"` {
			t.Errorf("%s: WWW-Authenticate = %q, want %q", path, got, `Basic realm="Restricted"`)
		}
	}
}
