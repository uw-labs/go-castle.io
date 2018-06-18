package castleio

import (
	"net/http"
	"github.com/tomasen/realip"
	"bytes"
	"encoding/json"
)

// TrackEndpoint defines the tracking URL castle.io side
var TrackEndpoint = "https://api.castle.io/v1/track"

// Event is an enum defining types of event castle tracks
type Event string

const (
	EventLoginSucceeded Event = "$login.succeeded"
)

// New creates a new castle client
func New(secret string) (*Castle, error) {
	client := &http.Client{}

	return NewWithHTTPClient(secret, client)
}

// HeaderWhitelist keeps a list of headers that will be forwarded to castle
var HeaderWhitelist = []string{"USER-AGENT", "ACCEPT", "ACCEPT-LANGUAGE", "ACCEPT-ENCODING"}

// NewWithHTTPClient same as New but allows passing of http.Client with custom config
func NewWithHTTPClient(secret string, client *http.Client) (*Castle, error) {
	return &Castle{client: client, apiSecret: secret}, nil
}

// Castle encapsulates http client
type Castle struct {
	client *http.Client
	apiSecret string
}

//TODO PICK HEADERS FROM REQUEST

type Context struct {
	ClientID string
	IP string
	Headers map[string]string
}

func getClientID(r *http.Request) string {

	var clientID string

	// ClientID is __cid cookie or X-Castle-Client-Id header
	cidCookie, _ := r.Cookie("__cid")

	if cidCookie != nil {
		clientID = cidCookie.Value
	}

	cidHeader := r.Header.Get("HTTP_X_CASTLE_CLIENT_ID")

	if cidHeader != "" {
		clientID = cidHeader
	}

	return clientID
}

func isHeaderWhitelisted(header string) bool {
	for _, whitelistedHeader := range HeaderWhitelist {

		if header == http.CanonicalHeaderKey(whitelistedHeader) {
			return true
		}
	}
	return false
}

// ContextFromRequest builds castle context from current http.Request
func ContextFromRequest(r *http.Request) *Context {

	headers := make(map[string]string)

	for requestHeader := range r.Header {
		if isHeaderWhitelisted(requestHeader) {
			headers[requestHeader] = r.Header.Get(requestHeader)
		}
	}

	return &Context{ClientID: getClientID(r), IP: realip.FromRequest(r), Headers: headers}
}

type castleTrackRequest struct {
	Event Event	`json:"event"`
	UserID string `json:"user_id"`
	Context *Context `json:"context"`
	Properties map[string]string `json:"properties"`
	UserTraits map[string]string `json:"user_traits"`
}

// Track sends a tracking request to castle.io
// see https://castle.io/docs/events for details
func (c *Castle) Track(event Event, userID string, properties map[string]string, userTraits map[string]string, context *Context) (error) {

	e := &castleTrackRequest{Event: event, UserID: userID, Context: context, Properties: properties, UserTraits: userTraits}
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(e)

	req, err := http.NewRequest(http.MethodPost, TrackEndpoint, b)
	req.SetBasicAuth("", c.apiSecret)

	if err != nil {
		return err
	}

	_, err = c.client.Do(req)

	return err
}

// TrackSimple allows simple tracking of events into castle without specifying traits or properties
func (c *Castle) TrackSimple(event Event, userID string, context *Context) error {
	e := &castleTrackRequest{Event: event, UserID: userID, Context: context}
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(e)

	req, err := http.NewRequest(http.MethodPost, TrackEndpoint, b)
	req.SetBasicAuth("", c.apiSecret)

	if err != nil {
		return err
	}

	_, err = c.client.Do(req)

	return err
}



