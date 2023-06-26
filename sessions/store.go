package sessions

import (
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
)

type CookieOptions struct {
	Name   string
	Path   string
	Domain string
	// MaxAge=0 means no Max-Age attribute specified and the cookie will be
	// deleted after the browser session ends.
	// MaxAge<0 means delete cookie immediately.
	// MaxAge>0 means Max-Age attribute present and given in seconds.
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

type Store struct {
	kv   nats.KeyValue
	opts *CookieOptions
}

func New(kv nats.KeyValue, opts *CookieOptions) *Store {
	return &Store{
		kv:   kv,
		opts: opts,
	}
}

func (s *Store) Get(r *http.Request, provider string) (*Session, error)

func (s *Store) New(r *http.Request, name string) (*Session, error) {
	session := NewSession()
	session.IsNew = true

	c, err := r.Cookie(name)
	if err != nil {
		return nil, err
	}

	if err := session.Deserialize([]byte(c.Value)); err != nil {
		return nil, err
	}

	ok, err := s.load(session)
	if err != nil {
		return nil, err
	}

	session.IsNew = !(err == nil && ok) // not new if no error and data available

	return session, err
}

func (s *Store) Save(r *http.Request, w http.ResponseWriter, ss *Session) error {
	if err := s.save(ss); err != nil {
		return err
	}

	bs, err := ss.Serialize()
	if err != nil {
		return err
	}
	http.SetCookie(w, newCookie(string(bs), s.opts))
	return nil
}

func newCookie(value string, opts *CookieOptions) *http.Cookie {
	cookie := &http.Cookie{
		Name:     opts.Name,
		Value:    value,
		Path:     opts.Path,
		MaxAge:   opts.MaxAge,
		Secure:   opts.Secure,
		HttpOnly: opts.HttpOnly,
		SameSite: opts.SameSite,
	}

	if opts.MaxAge > 0 {
		d := time.Duration(opts.MaxAge) * time.Second
		cookie.Expires = time.Now().Add(d)
	} else if opts.MaxAge < 0 {
		// Set it to the past to expire now.
		cookie.Expires = time.Unix(1, 0)
	}

	return cookie
}

func (s *Store) save(ss *Session) error {
	bs, err := ss.Serialize()
	if err != nil {
		return err
	}
	_, err = s.kv.Put(ss.ID, bs)

	return err
}

func (s *Store) load(ss *Session) (bool, error) {
	data, err := s.kv.Get(ss.ID)
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, nil
	}

	return true, ss.Deserialize(data.Value())
}

func (s *Store) delete(ss *Session) error {
	return s.kv.Delete(ss.ID)
}
