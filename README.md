# go-castle.io

go-castle.io is a go library wrapping https://castle.io API.

## Install

```
go get github.com/utilitywarehouse/go-castle.io
```

## Tracking

### Example

```go
package main

import (
	"net/http"
	"github.com/utilitywarehouse/go-castle.io/castleio"
	"log"
)

func main() {

	castle, err := castleio.New("secret-api-key")

	if err != nil {
		log.Fatal(err)
	}

	http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// authenticate user then track with castle

		err := castle.TrackSimple(
		    castleio.EventLoginSucceeded,
		    "user-123",
		    castleio.ContextFromRequest(r)
        )

		if err != nil {
			log.Println(err)
		}

		w.WriteHeader(http.StatusNoContent)
	}))

}
```

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