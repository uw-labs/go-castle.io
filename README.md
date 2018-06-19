# go-castle.io [![Build Status](https://travis-ci.org/uw-labs/go-castle.io.svg?branch=master)](https://travis-ci.org/uw-labs/go-castle.io)

go-castle.io is a go library wrapping https://castle.io API.

## Install

```
go get github.com/utilitywarehouse/go-castle.io
```

## Usage

### Providing own http client

```go
castleio.NewWithHTTPClient("secret-api-key", &http.Client{Timeout: time.Second * 2})
```

### Tracking properties and traits

```go
castle.Track(
		castleio.EventLoginSucceeded,
		"user-123",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castleio.ContextFromRequest(req),
	)
```

### Tracking custom events

```go
castle.Track(
		castleio.Event("custom-event"),
		"user-123",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castleio.ContextFromRequest(req),
	)
```

### Adaptive authentication

```go
decision, err := castle.Authenticate(
		castleio.EventLoginSucceeded,
		"md-1",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castleio.ContextFromRequest(req),
	)
```

### Example

```go
package main

import (
	"github.com/utilitywarehouse/go-castle.io/castleio"
	"net/http"
	"log"
)

func main() {

	castle, err := castleio.New("secret-api-key")

	if err != nil {
		log.Fatal(err)
	}

	http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// authenticate user then track with castle

		decision, err := castle.AuthenticateSimple(
			castleio.EventLoginSucceeded,
			"user-123",
			castleio.ContextFromRequest(r),
		)

		if err != nil {
			log.Println(err)
		}

		if decision == castleio.RecommendedActionChallenge {
			// challenge with MFA and track with castle

			err := castle.TrackSimple(
				castleio.EventChallengeRequested,
				"user-123",
				castleio.ContextFromRequest(r),
			)

			if err != nil {
				log.Println(err)
			}

			// trigger off MFA path
		}

		w.WriteHeader(http.StatusNoContent)
	}))

}
```