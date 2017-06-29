package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/oauth2"

	"github.com/ifo/oauth2rc"
	"github.com/pressly/chi"
	"github.com/pressly/chi/middleware"
)

func main() {
	var port = flag.Int("port", 3000, "Port to run the server on")

	flag.Parse()

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Serve assets
	r.FileServer("/assets/", http.Dir("assets"))

	// Routes
	r.Get("/", indexHandler)

	// Cleanup or Remove
	r.Get("/rc/me", rcHandler)
	r.Get("/rc/token", goToTokenHandler)
	r.Get("/rc/enter", enterTokenHandler)
	r.Post("/rc/enter", submitTokenHandler)

	// Helper functions. Remove later.
	r.Get("/headers", headersHandler)

	http.ListenAndServe(fmt.Sprintf(":%d", *port), r)
}

/*
// Handlers
*/

func indexHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("templates/index.html")
	tmpl.Execute(w, nil)
}

/*
// Cleanup or remove later
*/

// global var for the token string.
var token *oauth2.Token

// See what headers come through.
func headersHandler(w http.ResponseWriter, r *http.Request) {
	for k, v := range r.Header {
		fmt.Fprintln(w, k, v)
	}
}

// Get rc/me using a saved token.
func rcHandler(w http.ResponseWriter, r *http.Request) {
	if token == nil {
		http.Redirect(w, r, "/rc/token", 302)
		return
	}
	// We have a token now.
	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint:     oauth2rc.Endpoint,
	}
	client := oauth2.NewClient(ctx, conf.TokenSource(ctx, token))

	resp, err := client.Get("https://www.recurse.com/api/v1/people/me")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var jsonBody bytes.Buffer
	err = json.Indent(&jsonBody, body, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	w.Write(jsonBody.Bytes())
}

func goToTokenHandler(w http.ResponseWriter, r *http.Request) {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint:     oauth2rc.Endpoint,
	}

	// Redirect user to consent page to ask for permission for this app.
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, 302)
}

func enterTokenHandler(w http.ResponseWriter, r *http.Request) {
	tokenForm := `<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" href="/assets/css/tachyons.min.css" />
    <link rel="stylesheet" href="/assets/css/site.css" />
  </head>
  <body>
    <header>
      <div class="tc w-100 w-50-ns">
        <h1>OSS Reading Club</h1>
      </div>
    </header>
    <main>
      <p>Submit your token:</p>
      <form action='/rc/enter' method='post'>
        <input type='text' name='token' />
				<button type='submit'>Submit</button>
      </form>
    </main>
  </body>
</html>`
	tmpl := template.Must(template.New("tokenform").Parse(tokenForm))
	tmpl.Execute(w, nil)
}

func submitTokenHandler(w http.ResponseWriter, r *http.Request) {
	code := r.PostFormValue("token")
	if code == "" {
		w.WriteHeader(500)
		w.Write([]byte("no token received"))
		return
	}

	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint:     oauth2rc.Endpoint,
	}

	tok, err := conf.Exchange(ctx, code)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte(err.Error()))
		return
	}

	// Save the global token.
	token = tok

	http.Redirect(w, r, "/rc/me", 302)
}
