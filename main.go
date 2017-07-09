package main

import (
	"context"
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
	"golang.org/x/oauth2"
)

func main() {
	portStr := os.Getenv("PORT")
	portDefault := 3000
	var err error
	if portStr != "" {
		portDefault, err = strconv.Atoi(portStr)
	}
	if err != nil {
		log.Fatal(err)
	}
	var port = flag.Int("port", portDefault, "Port to run the server on")

	flag.Parse()

	engine := memstore.New(5 * time.Minute)
	sessionManager := session.Manage(engine)

	r := chi.NewRouter()

	// TODO: Audit middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
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
	// TODO: Add logout

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
	// TODO: randomize state
	url := conf.AuthCodeURL("state", oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, 302)
}

// Finish the OAuth2 process.
func redirectHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: check state
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "no token received", 500)
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

	// TODO: keep track of where to redirect the user
	http.Redirect(w, r, "/", 302)
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
