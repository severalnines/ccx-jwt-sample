package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

//go:embed web/*
var webFiles embed.FS

var (
	ErrBadPEMData = errors.New("malformed PEM data")
)

type jwtLoginRequest struct {
	Issuer    string `json:"issuer"`
	Token     string `json:"jwt"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func privateRSAKeyFromPEM(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, ErrBadPEMData
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func createJWT(issuer, subject string, exp time.Duration, key *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer,
		"sub": subject,
		"jti": uuid.NewString(),
		"iat": now.Unix(),
		"exp": now.Add(exp).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
}

func sendError(w http.ResponseWriter, msg string, err error) {
	w.WriteHeader(200)
	_, err = w.Write([]byte(msg + ", " + err.Error()))
	if err != nil {
		slog.Error("write to client", "err", err)
		os.Exit(1)
	}
}

func main() {
	bind := flag.String("bind", "0.0.0.0:8088", "where to bind")
	cloud := flag.String("cloud", "mycloud", "cloud name, configured in CCX")
	keyPath := flag.String("keyfile", "key.pem", "path of private key")
	ccxURL := flag.String("ccx", "https://ccx.s9s-dev.net/api/auth", "CCX auth URL")
	insecure := flag.Bool("insecure", false, "skip TLS verification when calling CCX (local dev only)")

	flag.Parse()

	httpClient := &http.Client{Timeout: 5 * time.Second}
	if *insecure {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient.Transport = transport
	}

	keyBytes, err := os.ReadFile(*keyPath)
	if err != nil {
		slog.Error("read private key file", "err", err)
		os.Exit(1)
	}

	privKey, err := privateRSAKeyFromPEM(keyBytes)
	if err != nil {
		slog.Error("load private key", "err", err)
		os.Exit(1)
	}

	// make web server

	files, err := fs.Sub(webFiles, "web")
	if err != nil {
		slog.Error("make web fs", "err", err)
		os.Exit(1)
	}

	lr, err := net.Listen("tcp", *bind)
	if err != nil {
		slog.Error("bind port", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, files, r.URL.Path)
	})

	// makeLoginURL reads the user details from the form (normally these would
	// come from the user's session), creates a JWT, posts it to CCX to check
	// that it is accepted, and returns the URL that logs the browser into CCX.
	makeLoginURL := func(r *http.Request) (string, error) {
		err := r.ParseForm()
		if err != nil {
			return "", fmt.Errorf("parse form: %w", err)
		}

		userID := r.Form.Get("userid")
		if userID == "" {
			return "", fmt.Errorf("missing userid")
		}

		name1 := r.Form.Get("name1")
		if name1 == "" {
			return "", fmt.Errorf("missing name1")
		}

		name2 := r.Form.Get("name2")
		if name2 == "" {
			return "", fmt.Errorf("missing name2")
		}

		// create the JWT

		token, err := createJWT(*cloud, userID, 15*time.Minute, privKey)
		if err != nil {
			return "", fmt.Errorf("create JWT: %w", err)
		}

		// post the JWT to CCX

		in := &jwtLoginRequest{
			Issuer:    *cloud,
			Token:     token,
			FirstName: name1,
			LastName:  name2,
		}

		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(in); err != nil {
			return "", fmt.Errorf("json encode: %w", err)
		}

		req, err := http.NewRequest(http.MethodPost, *ccxURL+"/jwt-login", &buf)
		if err != nil {
			return "", fmt.Errorf("make HTTP request: %w", err)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("post to CCX: %w", err)
		}
		defer resp.Body.Close()

		// check that the JWT was accepted

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("CCX post: status code: %d\n%s", resp.StatusCode, body)
		}

		return fmt.Sprintf("%s/jwt-login?jwt=%s&issuer=%s", *ccxURL, token, *cloud), nil
	}

	mux.HandleFunc("POST /login-to-ccx", func(w http.ResponseWriter, r *http.Request) {
		loginURL, err := makeLoginURL(r)
		if err != nil {
			sendError(w, "login", err)
			return
		}

		// send the user to CCX with the token - a top-level navigation, so the
		// session cookie is accepted with the browser's default SameSite=Lax

		http.Redirect(w, r, loginURL, http.StatusSeeOther)
	})

	mux.HandleFunc("POST /embed-ccx", func(w http.ResponseWriter, r *http.Request) {
		loginURL, err := makeLoginURL(r)
		if err != nil {
			http.Error(w, "login: "+err.Error(), http.StatusBadGateway)
			return
		}

		// the page sets this URL as the iframe src - a cross-site request that
		// is not a top-level navigation, so the browser rejects the session
		// cookie unless CCX is configured with SESSION_COOKIE_SAMESITE=none

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"url": loginURL})
	})

	// serve

	srv := http.Server{
		Handler: mux,
	}

	fmt.Printf("listening at http://%s\n", lr.Addr())

	err = srv.Serve(lr)
	if !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server", "err", err)
	}
}
