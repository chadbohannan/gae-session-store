package gaess

import (
	"fmt"
	"net/http"
	"strconv"

	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// TODO objectify SessionStore
// TODO extend SessionStore to exploit memcache

// Session encapsulates the minimum gorillia session interface parameters
type Session struct {
	Created int64
	Updated int64
	UserID  int64
}

// SessionStore persists sessions to App Engine datastore. An application should
// need exactly one instance.
type SessionStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
	kind    string
}

// NewSessionStore returns a new SessionStore.
// kind is the Google Datastore Entity Kind name used to persist session data.
//   you are are recommended to use 'Session' if it is not already in use.
// key is a hash key used to define session Codexs.
// See NewCookieStore() for a description of the other parameters.
func NewSessionStore(kind string, key string, maxAge int) *SessionStore {
	return &SessionStore{
		Codecs: securecookie.CodecsFromPairs([]byte(key)),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: maxAge,
		},
		kind: kind,
	}
}

// GetSession wraps a Get call which satisfies a gorilla interface.
func (s *SessionStore) GetSession(r *http.Request) *sessions.Session {
	session, _ := s.Get(r, "usersession")
	return session
}

// Get returns a session for the given name after adding it to the registry.
// See CookieStore.Get().
func (s *SessionStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
// See CookieStore.New().
func (s *SessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	session.Options = &(*s.Options)
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		if err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...); err == nil {
			if err = s.load(r, session); err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save adds a single session to the response.
func (s *SessionStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if err := s.save(r, session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

// save writes encoded in session.Values to datastore.
func (s *SessionStore) save(r *http.Request, session *sessions.Session) error {
	c := appengine.NewContext(r)
	var key *datastore.Key
	if session.ID == "" {
		key = datastore.NewIncompleteKey(c, s.kind, nil)
	} else {
		keyID, _ := strconv.ParseInt(session.ID, 10, 64)
		key = datastore.NewKey(c, s.kind, "", keyID, nil)
	}
	key, err := datastore.Put(c, key, &Session{
		Created: session.Values[createdParam].(int64),
		Updated: Now(),
		UserID:  session.Values[idParam].(int64),
	})
	session.ID = fmt.Sprintf("%d", key.IntID())
	// log.Infof(c, "sessions:saved:%s, userID:%d", session.ID, session.Values[idParam].(int64))
	return err
}

// load reads session content from datastore and copies it into session.Values.
func (s *SessionStore) load(r *http.Request, session *sessions.Session) error {
	c := appengine.NewContext(r)
	// log.Infof(c, "load, session:%s, kind:%s", session.ID, s.kind)
	keyID, _ := strconv.ParseInt(session.ID, 10, 64)
	key := datastore.NewKey(c, s.kind, "", keyID, nil)
	entity := Session{}
	if err := datastore.Get(c, key, &entity); err != nil {
		log.Errorf(c, "error loading ")
		return err
	}
	session.Values[createdParam] = entity.Created
	session.Values[updatedParam] = entity.Updated
	session.Values[idParam] = entity.UserID
	return nil
}
