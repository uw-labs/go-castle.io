package castleio_test

import (
	"testing"
	"net/http"
	"github.com/utilitywarehouse/go-castle.io/castleio"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"encoding/json"
)

func configureRequest() *http.Request {
	req := httptest.NewRequest("GET", "/", nil)

	req.Header.Set("HTTP_X_CASTLE_CLIENT_ID", "__cid_header")
	req.Header.Set("X-FORWARDED-FOR", "6.6.6.6, 3.3.3.3, 8.8.8.8")
	req.Header.Set("USER-AGENT", "some-agent")

	return req
}

func TestCastle_Track(t *testing.T) {

	req := configureRequest()

	castle, _ := castleio.New("secret-string")

	var executed = false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type castleTrackRequest struct {
			Event castleio.Event	`json:"event"`
			UserID string `json:"user_id"`
			Context *castleio.Context `json:"context"`
			Properties map[string]string `json:"properties"`
			UserTraits map[string]string `json:"user_traits"`
		}

		reqData := &castleTrackRequest{}

		username, password, ok := r.BasicAuth()

		assert.Empty(t, username)
		assert.Equal(t, password, "secret-string")
		assert.True(t, ok)

		json.NewDecoder(r.Body).Decode(reqData)

		assert.Equal(t, castleio.EventLoginSucceeded, reqData.Event)
		assert.Equal(t, "user-id", reqData.UserID)
		assert.Equal(t, map[string]string{"prop1": "propValue1"}, reqData.Properties)
		assert.Equal(t, map[string]string{"trait1": "traitValue1"}, reqData.UserTraits)
		assert.Equal(t, castleio.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castleio.TrackEndpoint = ts.URL

	castle.Track(
		castleio.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castleio.ContextFromRequest(req),
	)

	assert.True(t, executed)

}

func TestCastle_TrackSimple(t *testing.T) {
	req := configureRequest()

	castle, _ := castleio.New("secret-string")

	var executed = false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type castleTrackRequest struct {
			Event castleio.Event	`json:"event"`
			UserID string `json:"user_id"`
			Context *castleio.Context `json:"context"`
		}

		reqData := &castleTrackRequest{}

		username, password, ok := r.BasicAuth()

		assert.Empty(t, username)
		assert.Equal(t, password, "secret-string")
		assert.True(t, ok)

		json.NewDecoder(r.Body).Decode(reqData)

		assert.Equal(t, castleio.EventLoginSucceeded, reqData.Event)
		assert.Equal(t, "user-id", reqData.UserID)
		assert.Equal(t, castleio.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castleio.TrackEndpoint = ts.URL

	castle.TrackSimple(
		castleio.EventLoginSucceeded,
		"user-id",
		castleio.ContextFromRequest(req),
	)

	assert.True(t, executed)
}

func TestContextFromRequest(t *testing.T) {

	// grabs ClientID form cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name: "__cid",
		Value: "__cid_value",
	})

	ctx := castleio.ContextFromRequest(req)
	assert.Equal(t, "__cid_value", ctx.ClientID)

	// prefers header to cookie
	req.Header.Set("HTTP_X_CASTLE_CLIENT_ID", "__cid_header")

	ctx = castleio.ContextFromRequest(req)
	assert.Equal(t, "__cid_header", ctx.ClientID)

	// grabs IP from request
	req.Header.Set("X-REAL-IP", "9.9.9.9")
	ctx = castleio.ContextFromRequest(req)
	assert.Equal(t, "9.9.9.9", ctx.IP)

	// but prefers X-FORWARDED-FOR
	req.Header.Set("X-FORWARDED-FOR", "6.6.6.6, 3.3.3.3, 8.8.8.8")
	ctx = castleio.ContextFromRequest(req)
	assert.Equal(t, "6.6.6.6", ctx.IP)

	// grabs whitelisted headers only

	for _, whitelistedHeader := range castleio.HeaderWhitelist {
		req.Header.Set(whitelistedHeader, whitelistedHeader )
	}

	ctx = castleio.ContextFromRequest(req)
	for _, whitelistedHeader := range castleio.HeaderWhitelist {
		assert.Contains(t, ctx.Headers, http.CanonicalHeaderKey(whitelistedHeader))
	}

	assert.NotContains(t, ctx.Headers, "Cookie")

}