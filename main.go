package main

import (
	"bytes"
	"crypto/rsa"
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

	flag.Parse()

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

	mux.HandleFunc("POST /login-to-ccx", func(w http.ResponseWriter, r *http.Request) {
		// read the user details - normally this would come from the user's session

		err := r.ParseForm()
		if err != nil {
			sendError(w, "parse form", err)
			return
		}

		userID := r.Form.Get("userid")
		if userID == "" {
			sendError(w, "CCX post", fmt.Errorf("missing userid"))
			return
		}

		name1 := r.Form.Get("name1")
		if name1 == "" {
			sendError(w, "CCX post", fmt.Errorf("missing name1"))
			return
		}

		name2 := r.Form.Get("name2")
		if name2 == "" {
			sendError(w, "CCX post", fmt.Errorf("missing name2"))
			return
		}

		// create the JWT

		token, err := createJWT(*cloud, userID, 15*time.Minute, privKey)
		if err != nil {
			sendError(w, "create JWT", err)
			return
		}

		// post the JWT to CCX

		client := &http.Client{Timeout: 5 * time.Second}
		in := &jwtLoginRequest{
			Issuer:    *cloud,
			Token:     token,
			FirstName: name1,
			LastName:  name2,
		}

		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(in); err != nil {
			sendError(w, "json encode", err)
			return
		}

		req, err := http.NewRequest(http.MethodPost, *ccxURL+"/jwt-login", &buf)
		if err != nil {
			sendError(w, "make HTTP resqueset", err)
			return
		}

		resp, err := client.Do(req)
		if err != nil {
			sendError(w, "post to CCX", err)
			return
		}
		defer resp.Body.Close()

		// check that the JWT was accepted

		if resp.StatusCode != http.StatusOK {
			sendError(w, "CCX post", fmt.Errorf("status code: %d", resp.StatusCode))
			w.Write([]byte("\n"))
			io.Copy(w, resp.Body)
			return
		}

		// send the user to CCX with the token

		redirectTo := fmt.Sprintf("%s/jwt-login?jwt=%s&issuer=%s", *ccxURL, token, *cloud)

		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
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
