package sessions

import (
	"bytes"
	"encoding/gob"

	"github.com/google/uuid"
	"github.com/rapidmidiex/oauth"
)

type Session struct {
	ID       string
	IsNew    bool
	Sessions map[string]oauth.Session
}

func NewSession() *Session {
	return &Session{
		ID: uuid.NewString(),
	}
}

func (s *Session) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(s.Sessions)
	if err == nil {
		return buf.Bytes(), nil
	}
	return nil, err
}

func (s *Session) Deserialize(bs []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(bs))
	return dec.Decode(&s.Sessions)
}
