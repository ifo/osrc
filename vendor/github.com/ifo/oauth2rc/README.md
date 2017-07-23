oauth2rc
========

Use this with go's [oauth2 package](https://godoc.org/golang.org/x/oauth2).

Quick Usage Example
-------------------

Heavily copied from the oauth2 godoc config example.

```go
import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/ifo/oauth2rc"
	"golang.org/x/oauth2"
)

func main() {
	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"), 
		// RedirectURL = "urn:ietf:wg:oauth:2.0:oob" for local testing only.
		//Scopes:       []string{""},
		// Scopes aren't necessary in this case.
		Endpoint:     oauth2rc.Endpoint,
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	fmt.Printf("Visit the URL for the auth dialog: %v", url)

	// Use the authorization code that is pushed to the redirect
	// URL. Exchange will do the handshake to retrieve the
	// initial access token. The HTTP Client returned by
	// conf.Client will refresh the token as necessary.
	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatal(err)
	}
	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		log.Fatal(err)
	}

	client := conf.Client(ctx, tok)
	resp, err := client.Get("https://www.recurse.com/api/v1/people/me")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Pretty print the response.
	var jsonBody bytes.Buffer
	err = json.Indent(&jsonBody, body, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	// You should see some info about yourself.
	fmt.Println(jsonBody.String())
}
```
