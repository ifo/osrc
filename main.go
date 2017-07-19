package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/alexedwards/scs/engine/memstore"
	"github.com/alexedwards/scs/session"
	"github.com/ifo/oauth2rc"
	"github.com/pressly/chi"
	"github.com/pressly/chi/middleware"
	"github.com/pressly/lg"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// TODO: use an actual database
type OSSDB struct {
	O []OSS
	sync.Mutex
}

type VoteDB struct {
	M map[Vote]struct{}
	sync.Mutex
}

var ossDB = OSSDB{}
var voteDB = VoteDB{M: map[Vote]struct{}{}}

var templates *template.Template

func main() {
	// Setup
	// Get the server port.
	portStr := os.Getenv("PORT")
	portDefault := 3000
	var err error
	if portStr != "" {
		portDefault, err = strconv.Atoi(portStr)
	}
	if err != nil {
		log.Fatal(err)
	}
	port := flag.Int("port", portDefault, "Port to run the server on")

	// Parse the templates.
	templates = template.Must(template.ParseGlob(filepath.Join("templates", "partials", "*.tmpl")))
	templates = template.Must(templates.ParseGlob(filepath.Join("templates", "*.tmpl")))

	// Ensure logging directory exists.
	if err := os.Mkdir("logs", 0755); err != nil && !os.IsExist(err) {
		log.Fatalf("error making directory: %v", err)
	}
	f, err := os.OpenFile("logs/server.logs", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	logger := logrus.New()
	logger.Out = f

	flag.Parse()

	// Execute
	engine := memstore.New(5 * time.Minute)
	sessionManager := session.Manage(engine)

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(lg.RequestLogger(logger))
	r.Use(middleware.Recoverer)

	// Serve assets
	r.FileServer("/assets/", http.Dir("assets"))

	r.Get("/", indexHandler)
	r.Get("/rc/login", loginHandler)
	r.Get("/rc/redirect", redirectHandler)
	r.Get("/logout", logoutHandler)

	r.Route("/oss", func(r chi.Router) {
		r.With(Auth)
		r.Post("/", ossPostHandler)
	})

	http.ListenAndServe(fmt.Sprintf(":%d", *port), sessionManager(r))
}

/*
// Types
*/

// A vote is a positive point for an OSS project.
// Users who propose a project can't also vote for it.
type Vote struct {
	UserID int
	OSSID  int
}

// OSS is a project that someone has proposed to read.
type OSS struct {
	ID          int
	Name        string
	URL         *url.URL
	Description string // Optional
	Votes       int    // This is a cache of the votes table
	SubmitterID int    // This is a User.ID
}

// Used to store a user, and also parse user information from an endpoint.
type User struct {
	ID   int    `json:"id"`
	Name string `json:"first_name"`
}

/*
// Middleware
*/

// Auth ensures that a user is authed.
func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, _ := session.GetString(r, "username")
		if username == "" {
			// It is okay if this fails, we'll just redirect to "/" later.
			session.PutString(r, "redirect", r.URL.Path)
			http.RedirectHandler("/rc/login", 302).ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

/*
// Handlers
*/

// indexHandler requires a user to be authed.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUser(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	templates.ExecuteTemplate(w, "index.tmpl", struct{ User User }{User: user})
}

// Start the OAuth2 process.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint:     oauth2rc.Endpoint,
	}

	// Make a random state string.
	randomBytes := make([]byte, 20)
	_, err := rand.Read(randomBytes)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Make it URL safe
	state := base64.RawURLEncoding.EncodeToString(randomBytes)

	// Set state to check later.
	err = session.PutString(r, "oauth2state", state)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Redirect user to consent page to ask for permission for this app.
	url := conf.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, 302)
}

// Finish the OAuth2 process.
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "no token received", 500)
		return
	}
	state := r.FormValue("state")
	sessionState, err := session.PopString(r, "oauth2state")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	if state != sessionState {
		http.Error(w, "state does not match", 500)
		return
	}

	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint:     oauth2rc.Endpoint,
	}

	token, err := conf.Exchange(ctx, code)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// Regenerate the session.
	err = session.RegenerateToken(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = setToken(r, token)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// set user
	err = retrieveAndSetUser(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	redirect, _ := session.PopString(r, "redirect")
	if redirect == "" {
		redirect = "/"
	}

	http.Redirect(w, r, redirect, 302)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	err := session.Clear(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	templates.ExecuteTemplate(w, "logout.tmpl", nil)
}

func ossPostHandler(w http.ResponseWriter, r *http.Request) {
	// Get the submitterID from the session userID.
	submitterID, err := session.GetInt(r, "userID")
	if err != nil {
		// Fail spectacularly because they shouldn't be here if they aren't logged in.
		http.Error(w, err.Error(), 500)
		return
	}

	name := r.PostFormValue("name")
	rawurl := r.PostFormValue("url")
	description := r.PostFormValue("description")

	// All form values must exist, except description.
	if name == "" || rawurl == "" {
		// TODO: handle this better; return a message to the form page
		http.Error(w, err.Error(), 500)
		return
	}

	// Remove any scheme fragments from the front of the url.
	for {
		if rawurl[:2] == "//" {
			rawurl = rawurl[2:]
		} else if rawurl[:1] == "/" || rawurl[:1] == ":" {
			rawurl = rawurl[1:]
		} else {
			break
		}
	}

	// To help with parsing, prepend "http://" if there's no scheme.
	if rawurl[:7] != "http://" || rawurl[:8] != "https://" {
		rawurl = "http://" + rawurl
	}

	// The URL must be a url.
	link, err := url.Parse(rawurl)
	if err != nil {
		// TODO: handle this better; return a message to the form page
		http.Error(w, err.Error(), 500)
		return
	}

	oss := OSS{
		Name:        name,
		URL:         link,
		Description: description,
		SubmitterID: submitterID,
	}

	// TODO: use an actual database
	ossDB.Lock()
	defer ossDB.Unlock()
	oss.ID = len(ossDB.O)
	ossDB.O = append(ossDB.O, oss)

	http.Redirect(w, r, "/", 302)
}

/*
// Session Storage
*/

// getUser will return whatever user is in the session, or an empty user
// if no user is logged in.
func getUser(r *http.Request) (User, error) {
	var user User
	if un, err := session.GetString(r, "username"); err != nil {
		return User{}, err
	} else {
		user.Name = un
	}
	if uid, err := session.GetInt(r, "userID"); err != nil {
		return User{}, err
	} else {
		user.ID = uid
	}
	return user, nil
}

func setUser(r *http.Request, user User) error {
	if user.Name == "" {
		return fmt.Errorf("can't set a nameless user")
	}

	if err := session.PutString(r, "username", user.Name); err != nil {
		return err
	}
	return session.PutInt(r, "userID", user.ID)
}

func getOauth2Client(r *http.Request) (*http.Client, error) {
	token, err := getToken(r)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, fmt.Errorf("user not authenticated")
	}
	ctx := context.Background()
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint:     oauth2rc.Endpoint,
	}
	return oauth2.NewClient(ctx, conf.TokenSource(ctx, token)), nil
}

// retrieveAndSetUser requires a valid OAuth2 token.
func retrieveAndSetUser(r *http.Request) error {
	client, err := getOauth2Client(r)
	if err != nil {
		return err
	}

	resp, err := client.Get("https://www.recurse.com/api/v1/people/me")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var user User
	err = json.Unmarshal(body, &user)
	if err != nil {
		return err
	}

	return setUser(r, user)
}

func setToken(r *http.Request, t *oauth2.Token) error {
	if err := session.PutString(r, "accesstoken", t.AccessToken); err != nil {
		return err
	}
	if err := session.PutString(r, "tokentype", t.TokenType); err != nil {
		return err
	}
	if err := session.PutString(r, "refreshtoken", t.RefreshToken); err != nil {
		return err
	}
	return session.PutTime(r, "expiry", t.Expiry)
}

func getToken(r *http.Request) (*oauth2.Token, error) {
	token := &oauth2.Token{}
	if at, err := session.GetString(r, "accesstoken"); err != nil {
		return nil, err
	} else {
		if at == "" { // We don't have a token yet
			return nil, fmt.Errorf("user not authenticated")
		}
		token.AccessToken = at
	}
	if tt, err := session.GetString(r, "tokentype"); err != nil {
		return nil, err
	} else {
		token.TokenType = tt
	}
	if rt, err := session.GetString(r, "refreshtoken"); err != nil {
		return nil, err
	} else {
		token.RefreshToken = rt
	}
	if exp, err := session.GetTime(r, "expiry"); err != nil {
		return nil, err
	} else {
		token.Expiry = exp
	}

	return token, nil
}
