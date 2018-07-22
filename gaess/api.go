package gaess

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

// now returns current time with millisecond resolution for browser compat
func now() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

// Now is an function pointer to facilitate override for test cases with time parameters
var Now = now

const idParam = "userID"
const createdParam = "created"
const updatedParam = "updated"

const oneWeek = 604800 // ms

// application singleton
var store = NewSessionStore("Session", "one one two three five", oneWeek)

// EndpointHandler extends an HTTP handler to accept
type EndpointHandler func(w http.ResponseWriter, r *http.Request, session *sessions.Session)

// HandleSessionAndRoute makes a passthrough call to the handler if a valid session exists
func HandleSessionAndRoute(w http.ResponseWriter, r *http.Request, f EndpointHandler, validate bool) {
	session := store.GetSession(r)
	if validate && !IsSessionValid(session) {
		response := map[string]interface{}{
			"error": "Not logged in.",
		}
		dataJSON, jsonErr := json.Marshal(response)
		w.Header().Set("Content-Type", "application/json")
		if jsonErr == nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(dataJSON)
		} else { // something mysterious is broken
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(jsonErr.Error()))
		}
	} else {
		f(w, r, session) // route request
	}
}

// SessionRoute is a convienience function that sets up HTTP routing with handler functions
// that accept a Session as a parameter
func SessionRoute(router *mux.Router, method, url string, handler EndpointHandler, validate bool) {
	router.HandleFunc(url, func(w http.ResponseWriter, r *http.Request) {
		HandleSessionAndRoute(w, r, handler, validate)
	}).Methods(method)
}

// IsSessionValid returns false for a session if it is new or its idParam is zero
func IsSessionValid(session *sessions.Session) bool {
	if session.IsNew || session.Values[idParam].(int64) == 0 {
		return false
	}
	return true
}

// LoginSession saves a session with userID set
func LoginSession(r *http.Request, w http.ResponseWriter, session *sessions.Session, userID int64) error {
	session.Values[idParam] = userID
	session.Values[updatedParam] = Now()
	return session.Save(r, w)
}

// LogoutSession saves a session with userID cleared
func LogoutSession(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	session.Values[idParam] = int64(0)
	session.Values[updatedParam] = Now()
	return session.Save(r, w)
}
