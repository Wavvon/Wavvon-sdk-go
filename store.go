package wavvon

import "sync"

// StateStore is where the SDK keeps state it must not lose: DH pins, DM
// ratchet sessions and group sender chains. Keys are opaque strings the SDK
// chooses ("dh-pin/<pubkey>", "dr/<conv>", "group-own/<conv>",
// "group-peer/<conv>/<sender>/<version>"); values are JSON. The default is
// in memory and lost when the process ends; a program that wants the state to
// survive a restart passes its own in ClientOptions.Store.
//
// Losing DM ratchet state leaves the conversations it belongs to unreadable,
// so a persistent implementation should make Put durable before it returns.
// Implementations must be safe for concurrent use. Get returns (nil, nil)
// for an absent key.
type StateStore interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Delete(key string) error
}

// MemoryStore is the default StateStore.
type MemoryStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

// Get implements StateStore.
func (s *MemoryStore) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), v...), nil
}

// Put implements StateStore.
func (s *MemoryStore) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[key] = append([]byte(nil), value...)
	return nil
}

// Delete implements StateStore.
func (s *MemoryStore) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}
