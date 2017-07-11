package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
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

func main() {
	// Setup
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

	// Routes
	r.Group(func(r chi.Router) {
		// Routes that require auth
		r.Use(Auth)

		r.Get("/", indexHandler)
	})

	r.Get("/rc/login", loginHandler)
	r.Get("/rc/redirect", redirectHandler)
	r.Get("/logout", logoutHandler)

	http.ListenAndServe(fmt.Sprintf(":%d", *port), sessionManager(r))
}

/*
// Types
*/

// Used to store a user, and also parse user information from an endpoint
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
	tmpl, _ := template.ParseFiles("templates/index.html")
	tmpl.Execute(w, struct{ User User }{User: user})
}

// Start the OAuth2 process.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		RedirectURL:  os.Getenv("REDIRECT_URL"),
		Endpoint:     oauth2rc.Endpoint,
	}

	// Redirect user to consent page to ask for permission for this app.
	state, err := makeState()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Set state to check later.
	err = session.PutString(r, "oauth2state", state)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

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
	w.Write([]byte("Bye bye!"))
}

/*
// Session Storage
*/

// getUser will error out if the session doesn't contain a valid user.
// Successfully getting a user means that the user is authenticated.
func getUser(r *http.Request) (User, error) {
	var user User
	if un, err := session.GetString(r, "username"); err != nil {
		return User{}, err
	} else {
		user.Name = un
	}

	// We didn't actually have a user in the session.
	if user.Name == "" {
		return User{}, fmt.Errorf("user not authenticated")
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

/*
// Crypto
*/

func makeState() (string, error) {
	randomBytes := make([]byte, 10)

	n, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}
	// Ensure we read enough random bytes.
	if n != len(randomBytes) {
		return "", fmt.Errorf("Not enough random bytes read")
	}

	// Save the sha sum so it becomes addressable.
	sum := sha1.Sum(randomBytes)
	// Make it URL safe
	return hex.EncodeToString(sum[:]), nil
}
