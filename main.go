package main

import (
	"context"
	"crypto/rand"
	"database/sql"
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
	"time"

	"github.com/alexedwards/scs/engine/memstore"
	"github.com/alexedwards/scs/session"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/ifo/oauth2rc"
	"github.com/pressly/lg"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	_ "github.com/mattn/go-sqlite3"
)

// ?TODO: put these in the default context?
var preparedStatements *PreparedStatements
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

	// Connect to the database.
	db, err := connectToDB()
	if err != nil {
		log.Fatal(err)
	}
	err = setupDB(db)
	if err != nil {
		log.Fatal(err)
	}
	preparedStatements, err = setupPreparedStatements(db)
	if err != nil {
		log.Fatal(err)
	}

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
	r.Handle("/assets/*", http.StripPrefix("/assets/", http.FileServer(http.Dir("assets"))))

	r.Get("/", indexHandler)
	r.Get("/rc/login", loginHandler)
	r.Get("/rc/redirect", redirectHandler)
	r.Get("/logout", logoutHandler)

	r.Route("/oss", func(r chi.Router) {
		r.Use(Auth)
		r.Get("/", ossFormHandler)
		r.Post("/", ossPostHandler)
		r.Route("/{ossID}", func(r chi.Router) {
			r.Use(ossContext)
			r.Get("/", ossHandler)
			r.Get("/edit", ossEditHandler)
			r.Post("/", ossUpdateHandler)
		})
	})

	http.ListenAndServe(fmt.Sprintf(":%d", *port), sessionManager(r))
}

/*
// Types and Database
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
	SubmitterID int    // This is a User.ID
	Votes       int
}

// Used to store a user, and also parse user information from an endpoint.
type User struct {
	ID   int    `json:"id"`
	Name string `json:"first_name"`
}

type PreparedStatements struct {
	GetOSS    *sql.Stmt
	GetAllOSS *sql.Stmt
	CreateOSS *sql.Stmt
	EditOSS   *sql.Stmt
	GetVotes  *sql.Stmt
	Vote      *sql.Stmt
	Unvote    *sql.Stmt
}

type OSSWithUser struct {
	OSS  OSS
	User User
}

func connectToDB() (*sql.DB, error) {
	// Ensure db directory exists.
	if err := os.Mkdir("db", 0755); err != nil && !os.IsExist(err) {
		return nil, err
	}
	return sql.Open("sqlite3", "file:db/sqlite.db")
}

func setupPreparedStatements(db *sql.DB) (*PreparedStatements, error) {
	statements := map[string]string{
		"GetOSS": `SELECT o.id, o.name, o.url, o.description, o.submitterid, COUNT(v.ossid) AS votes
		  FROM oss o
		  LEFT JOIN vote v ON o.id = v.ossid
		  WHERE id = $1
		  GROUP BY o.id, o.name, o.url, o.description, o.submitterid;`,
		"GetAllOSS": `SELECT o.id, o.name, o.url, o.description, o.submitterid, COUNT(v.ossid) AS votes
		  FROM oss o
		  LEFT JOIN vote v ON o.id = v.ossid
		  GROUP BY o.id, o.name, o.url, o.description, o.submitterid;`,
		"CreateOSS": "INSERT INTO oss (name, url, description, submitterid) VALUES ($1, $2, $3, $4);",
		"EditOSS":   "UPDATE oss SET name = $1, url = $2, description = $3 WHERE id = $4;",
		"GetVotes":  "SELECT COUNT(1) FROM vote WHERE ossid = $1;",
		"Vote":      "INSERT INTO vote (ossid, userid) VALUES ($1, $2);",
		"Unvote":    "DELETE FROM vote WHERE ossid = $1 AND userid = $2;",
	}

	stmts := map[string]*sql.Stmt{}

	for key, statement := range statements {
		stmt, err := db.Prepare(statement)
		if err != nil {
			return nil, err
		}
		stmts[key] = stmt
	}

	return &PreparedStatements{
		GetOSS:    stmts["GetOSS"],
		GetAllOSS: stmts["GetAllOSS"],
		CreateOSS: stmts["CreateOSS"],
		EditOSS:   stmts["EditOSS"],
		GetVotes:  stmts["GetVotes"],
		Vote:      stmts["Vote"],
		Unvote:    stmts["Unvote"],
	}, nil
}

func setupDB(db *sql.DB) error {
	ensureTables := []string{
		`CREATE TABLE IF NOT EXISTS oss (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			url TEXT UNIQUE NOT NULL,
			description TEXT,
			submitterid INT NOT NULL);`,
		`CREATE TABLE IF NOT EXISTS vote (
			ossid INTEGER NOT NULL,
			userid INTEGER NOT NULL);`,
	}

	ensureVoteIndexes := []string{
		"CREATE INDEX IF NOT EXISTS voteossindex ON vote (ossid);",
		"CREATE INDEX IF NOT EXISTS voteuserindex ON vote (userid);",
		"CREATE UNIQUE INDEX IF NOT EXISTS voteindex ON vote (ossid, userid);",
	}

	for _, stmt := range append(ensureTables, ensureVoteIndexes...) {
		_, err := db.Exec(stmt)
		if err != nil {
			return err
		}
	}
	return nil
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

func ossContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ossIDStr := chi.URLParam(r, "ossID")
		ossID, err := strconv.Atoi(ossIDStr)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		oss := OSS{}
		var urlstr string
		err = preparedStatements.GetOSS.QueryRow(ossID).Scan(
			&oss.ID, &oss.Name, &urlstr, &oss.Description, &oss.SubmitterID, &oss.Votes)
		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "couldn't find that one", 404)
			} else {
				http.Error(w, err.Error(), 500)
			}
			return
		}
		oss.URL, err = url.Parse(urlstr)
		// This really shouldn't ever fail here.
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		ctx := context.WithValue(r.Context(), "oss", oss)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

/*
// Handlers
*/

func indexHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUser(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	ossRows, err := preparedStatements.GetAllOSS.Query()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer ossRows.Close()

	ossesWithUser := []OSSWithUser{}

	for ossRows.Next() {
		var oss OSS
		var urlstr string
		ossRows.Scan(&oss.ID, &oss.Name, &urlstr, &oss.Description, &oss.SubmitterID, &oss.Votes)
		// This parse shouldn't ever fail.
		oss.URL, _ = url.Parse(urlstr)
		ossWithUser := OSSWithUser{OSS: oss, User: user}
		ossesWithUser = append(ossesWithUser, ossWithUser)
	}
	err = ossRows.Err()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	templates.ExecuteTemplate(w, "index.tmpl", struct {
		User  User
		OSSes []OSSWithUser
	}{
		User:  user,
		OSSes: ossesWithUser,
	})
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

func ossFormHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUser(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	templates.ExecuteTemplate(w, "ossform.tmpl", struct {
		User User
		OSS  bool // OSS must exist, or else a template that checks for .OSS specifically will fail.
	}{User: user, OSS: false})
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
	if _, err = url.Parse(rawurl); err != nil {
		// TODO: handle this better; return a message to the form page
		http.Error(w, err.Error(), 500)
		return
	}

	createResult, err := preparedStatements.CreateOSS.Exec(name, rawurl, description, submitterID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	ossID, err := createResult.LastInsertId()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/oss/%d", ossID), 302)
}

func ossHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUser(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	oss := r.Context().Value("oss").(OSS)
	// TODO: make a better display page
	templates.ExecuteTemplate(w, "oss.tmpl", OSSWithUser{User: user, OSS: oss})
}

func ossEditHandler(w http.ResponseWriter, r *http.Request) {
	user, err := getUser(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	oss := r.Context().Value("oss").(OSS)
	templates.ExecuteTemplate(w, "ossform.tmpl", OSSWithUser{User: user, OSS: oss})
}

func ossUpdateHandler(w http.ResponseWriter, r *http.Request) {
	name := r.PostFormValue("name")
	rawurl := r.PostFormValue("url")
	description := r.PostFormValue("description")

	oss := r.Context().Value("oss").(OSS)
	// At least one form value must be non-blank.
	if name == "" || rawurl == "" || description == "" {
		http.Redirect(w, r, fmt.Sprintf("/oss/%d", oss.ID), 302)
		return
	}

	// Modify the URL if it was given.
	if rawurl != "" {
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

		fmt.Println(rawurl[:7])
		// To help with parsing, prepend "http://" if there's no scheme.
		if rawurl[:7] != "http://" || rawurl[:8] != "https://" {
			rawurl = "http://" + rawurl
		}

		// The URL must be a url.
		if _, err := url.Parse(rawurl); err != nil {
			// TODO: handle this better; return a message to the form page
			http.Error(w, err.Error(), 500)
			return
		}
	}

	if name != "" {
		oss.Name = name
	}
	if rawurl == "" {
		rawurl = oss.URL.String()
	}
	if description != "" {
		oss.Description = description
	}

	res, err := preparedStatements.EditOSS.Exec(oss.Name, rawurl, oss.Description, oss.ID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Println(res.RowsAffected())

	http.Redirect(w, r, fmt.Sprintf("/oss/%d", oss.ID), 302)
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
