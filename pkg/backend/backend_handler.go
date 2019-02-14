package backend

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/autonubil/default-backend-operator/pkg/types"
	"github.com/autonubil/default-backend-operator/pkg/utils"
	oidc "github.com/coreos/go-oidc"
	raven "github.com/getsentry/raven-go"
	"github.com/golang/glog"
	"github.com/tdewolff/minify"
	minicss "github.com/tdewolff/minify/css"
	minihtml "github.com/tdewolff/minify/html"
	minijs "github.com/tdewolff/minify/js"
	minijson "github.com/tdewolff/minify/json"
	minisvg "github.com/tdewolff/minify/svg"
	minixml "github.com/tdewolff/minify/xml"
	"golang.org/x/net/context"
)

// A webhook handler with a "ServeHTTP" method:
type BackendHandler struct {
	Options *types.BackendOperatorOptions
}

type sessionInfo struct {
	IDToken string
	Claims  types.KnownClaims
}

func parseJWT(p string) ([]byte, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("oidc: malformed jwt, expected 3 parts got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt payload: %v", err)
	}
	return payload, nil
}

// Handle webhook requests:
func (backendHandler *BackendHandler) LoginHandler(responseWriter http.ResponseWriter, request *http.Request, code string, templateData *types.TemplateData) (*sessionInfo, error) {
	// this is a response?
	if request.URL.Query().Get("state") == code {
		ctx := context.Background()
		oauth2Token, err := templateData.OidcConfig.Config.Exchange(ctx, request.URL.Query().Get("code"))
		if err != nil {
			return nil, err
		}

		// Throw out tokens with invalid claims before trying to verify the token. This lets
		// us do cheap checks before possibly re-syncing keys.
		payload, err := parseJWT(oauth2Token.AccessToken)
		if err != nil {
			return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
		}

		glog.V(4).Info("OIDC Payload: %s", payload)

		claims := types.KnownClaims{}
		err = json.Unmarshal(payload, &claims)
		if err != nil {
			return nil, err
		}
		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if ok {

			var asBytes bytes.Buffer
			enc := gob.NewEncoder(&asBytes)

			sessionInfo := sessionInfo{
				IDToken: rawIDToken,
				Claims:  claims,
			}
			err := enc.Encode(sessionInfo)
			if err != nil {
				return nil, err
			}

			cookie := &http.Cookie{
				Name:     "oidc_token",
				Value:    base64.URLEncoding.EncodeToString(asBytes.Bytes()),
				SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(responseWriter, cookie)
			return &sessionInfo, nil
		}
	}
	return nil, nil
}

func (backendHandler *BackendHandler) LogoutHandler(responseWriter http.ResponseWriter, request *http.Request, templateData *types.TemplateData) error {
	// this is a response?
	cookie := &http.Cookie{
		Name:     "oidc_token",
		Value:    "",
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(responseWriter, cookie)

	sessionCookie := &http.Cookie{
		Name:     "oidc_session",
		Value:    "",
		MaxAge:   -1,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(responseWriter, sessionCookie)

	http.Redirect(responseWriter, request, "/", 302)
	return nil
}

func (backendHandler *BackendHandler) AuthPrepareHandler(responseWriter http.ResponseWriter, request *http.Request, templateData *types.TemplateData) (string, error) {
	if backendHandler.Options.OidcConfig.Provider != nil {
		sessionCookie, err := request.Cookie("oidc_session")
		if err != nil && err != http.ErrNoCookie {
			return "", err
		}
		if sessionCookie == nil {
			sessionCookie = &http.Cookie{
				Name:   "oidc_session",
				Value:  utils.RandStringBytesMask(16),
				MaxAge: 3600,
				// SameSite: http.SameSiteStrictMode,
			}
			http.SetCookie(responseWriter, sessionCookie)
		}

		var schema string
		if request.TLS != nil {
			schema = "https"
		} else {
			// behind a reverse proxy
			schema = request.Header.Get("X-Forwarded-Proto")
			if schema == "" {
				schema = "http"
			}
		}
		templateData.OidcConfig.Config.RedirectURL = fmt.Sprintf("%s://%s/auth", schema, request.Host)
		templateData.OidcConfig.LoginURL = templateData.OidcConfig.Config.AuthCodeURL(sessionCookie.Value)
		templateData.OidcConfig.LogoutURL = fmt.Sprintf("%s://%s/logout", schema, request.Host)

		return sessionCookie.Value, nil

	}
	return "", nil
}

func (backendHandler *BackendHandler) AuthHandler(responseWriter http.ResponseWriter, request *http.Request, code string, templateData *types.TemplateData) error {
	if backendHandler.Options.OidcConfig.Provider != nil {
		// cookie :OAuth_Token_Request_State
		var session *sessionInfo
		cookie, err := request.Cookie("oidc_token")
		if err == nil && cookie != nil {
			uDec, _ := base64.URLEncoding.DecodeString(cookie.Value)
			buf := bytes.NewBuffer(uDec)
			dec := gob.NewDecoder(buf)
			si := sessionInfo{}
			err = dec.Decode(si)
			if err == nil && si.IDToken != "" {
				glog.V(1).Info("Failed to read cookie (%s)", err.Error())
				session = &si
			} else {
				session = nil
			}
		}
		if session == nil && request.URL.Path == "/auth" {
			session, err = backendHandler.LoginHandler(responseWriter, request, code, templateData)
			if err != nil {
				glog.V(3).Infof("Failed to exchange token: %s", err.Error())
				http.Redirect(responseWriter, request, templateData.OidcConfig.LoginURL, 302)
			}
		}

		if session != nil {
			ctx := context.Background()
			var verifier = backendHandler.Options.OidcConfig.Provider.Verifier(&oidc.Config{ClientID: backendHandler.Options.OidcConfig.Config.ClientID})
			// Parse and verify ID Token payload.
			idToken, err := verifier.Verify(ctx, session.IDToken)
			if err != nil {
				glog.V(3).Infof("Failed to verify token: %s", err.Error())
				http.Redirect(responseWriter, request, templateData.OidcConfig.LoginURL, 302)
				return err
			}
			templateData.Claims = &session.Claims
			glog.V(1).Infof("%v -> %v", idToken, session.Claims)

		}
	}
	return nil
}

// Handle webhook requests:
func (backendHandler *BackendHandler) IndexHandler(responseWriter http.ResponseWriter, request *http.Request) {

	err := backendHandler.Options.RefreshTemplate()
	if err != nil {
		http.Error(responseWriter, fmt.Sprintf("Failed to read template:\n%v", err), http.StatusBadRequest)
		return
	}

	if backendHandler.Options.Template != nil {
		templateData := backendHandler.Options.InitTemplateData()

		code, err := backendHandler.AuthPrepareHandler(responseWriter, request, templateData)

		if err == nil {
			if request.URL.Path == "/logout" {
				backendHandler.LogoutHandler(responseWriter, request, templateData)
				return
			} else {
				err = backendHandler.AuthHandler(responseWriter, request, code, templateData)
			}
		}

		if backendHandler.Options.OidcConfig.Enforce && (err != nil || templateData.Claims == nil) {
			if err != nil {
				glog.V(2).Infof("Authentication is mandatory: %s", err.Error())
			} else {
				glog.V(3).Infof("Authentication is mandatory")

			}
			http.Redirect(responseWriter, request, templateData.OidcConfig.LoginURL, 302)
			return
		}

		if err != nil {
			raven.CaptureError(err, map[string]string{})
			glog.Errorf("Problem during authentication: %s", err)
			http.Error(responseWriter, "Problem during authentication", http.StatusBadRequest)
			return
		}

		responseWriter.WriteHeader(200)
		responseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
		responseWriter.Header().Set("X-Content-Type-Options", "nosniff")

		m := minify.New()
		m.AddFunc("text/css", minicss.Minify)
		m.AddFunc("text/html", minihtml.Minify)
		m.AddFunc("image/svg+xml", minisvg.Minify)
		m.AddFuncRegexp(regexp.MustCompile("^(application|text)/(x-)?(java|ecma)script$"), minijs.Minify)
		m.AddFuncRegexp(regexp.MustCompile("[/+]json$"), minijson.Minify)
		m.AddFuncRegexp(regexp.MustCompile("[/+]xml$"), minixml.Minify)

		mw := m.ResponseWriter(responseWriter, request)
		defer mw.Close()
		responseWriter = mw

		err = backendHandler.Options.Template.Execute(responseWriter, templateData)
		if err != nil {
			responseWriter.Write([]byte(fmt.Sprintf("<pre>Failed to render template:\n%v", err)))
			return
		}

	} else {
		data, err := json.Marshal(backendHandler.Options.Data)
		if err != nil {
			raven.CaptureError(err, map[string]string{})
			glog.Errorf("Failed to marshall services: %s", err)
			http.Error(responseWriter, "Failed to marshall services", http.StatusBadRequest)
			return
		}
		responseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
		responseWriter.Header().Set("X-Content-Type-Options", "nosniff")
		responseWriter.WriteHeader(200)
		content := string(data)
		fmt.Fprintln(responseWriter, content)
	}
}
