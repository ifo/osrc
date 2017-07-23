// Package oauth2rc provides constants for using OAuth2 to access the Recurse Center API.
package oauth2rc // import "github.com/ifo/oauth2rc"

import (
	"golang.org/x/oauth2"
)

// Endpoint is Github's OAuth 2.0 endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:  "https://www.recurse.com/oauth/authorize",
	TokenURL: "https://www.recurse.com/oauth/token",
}
