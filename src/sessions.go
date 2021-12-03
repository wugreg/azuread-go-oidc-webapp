package main

import (
	"encoding/base32"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/securecookie"
)

var sessionManager map[string]map[string]interface{}

func doHttpSession(w http.ResponseWriter, r *http.Request) string {
	httpSession, err := sessionStore.Get(r, SESSION_NAME)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	var sessionID string
	var ok bool
	if sessionID, ok = httpSession.Values[PRINCIPAL_SESSION_NAME].(string); !ok {
		// No http session found, create new one
		httpSession.ID = string(securecookie.GenerateRandomKey(32))
		httpSession.ID = strings.TrimRight(base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)), "=")
		sessionID = httpSession.ID

		httpSession.Values[PRINCIPAL_SESSION_NAME] = httpSession.ID
		if err = httpSession.Save(r, w); err != nil {
			fmt.Println(err)
			return ""
		}
	}

	return sessionID
}

func getSessionID(r *http.Request) string {
	session, err := sessionStore.Get(r, SESSION_NAME)
	if err != nil {
		fmt.Println(err)
		panic("Failed to get session")
	}

	sessionID, _ := session.Values[PRINCIPAL_SESSION_NAME].(string)
	return sessionID
}

func saveToSession(sessionID string, key string, val interface{}) {
	if sessionManager[sessionID] == nil {
		sessionManager[sessionID] = make(map[string]interface{})
	}
	sessionManager[sessionID][key] = val
}
