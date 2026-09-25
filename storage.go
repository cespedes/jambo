package jambo

import "sync"

// Storage persists the state that must survive process restarts and be
// reachable from every replica of a Server: OAuth refresh tokens and
// Shared Signals Framework (SSF) streams, including events queued for
// poll delivery.
//
// Server ships [MemoryStorage] as a default. A host integrating with a
// receiver that expects long-lived streams and refresh tokens (such as
// Apple Business Manager) should implement Storage itself, backed by
// whatever datastore it already runs, and install it with
// [Server.SetStorage] before serving traffic.
type Storage interface {
	SaveRefreshToken(rt RefreshToken) error
	GetRefreshToken(token string) (rt RefreshToken, ok bool, err error)
	DeleteRefreshToken(token string) error
	// DeleteRefreshTokensForClient removes every refresh token issued to
	// clientID. Server.RemoveClient calls this, so a client id that gets
	// reused later (e.g. NewClient after RemoveClient) never silently
	// inherits tokens issued to whatever previously had that id.
	DeleteRefreshTokensForClient(clientID string) error

	SaveStream(stream Stream) error
	GetStream(streamID string) (stream Stream, ok bool, err error)
	ListStreams(clientID string) ([]Stream, error)
	DeleteStream(streamID string) error

	// QueueEvent appends a signed Security Event Token pending poll delivery.
	QueueEvent(streamID string, event PendingEvent) error
	// PendingEvents returns up to max not-yet-acknowledged events for streamID,
	// oldest first. A max <= 0 means "no limit".
	PendingEvents(streamID string, max int) ([]PendingEvent, error)
	// AckEvent removes an event from the poll queue once the receiver has
	// acknowledged delivery. Acking an unknown (streamID, jti) is a no-op.
	AckEvent(streamID, jti string) error
}

// MemoryStorage is the default, in-memory [Storage]. It is fine for
// development or a single-process demo, but state is lost on restart —
// not suitable for a production SSF integration, where streams and
// refresh tokens must outlive process restarts and be visible to every
// replica handling requests from the receiver.
type MemoryStorage struct {
	mu            sync.Mutex
	refreshTokens map[string]RefreshToken
	streams       map[string]Stream
	events        map[string][]PendingEvent // streamID -> pending events, oldest first
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		refreshTokens: make(map[string]RefreshToken),
		streams:       make(map[string]Stream),
		events:        make(map[string][]PendingEvent),
	}
}

func (m *MemoryStorage) SaveRefreshToken(rt RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[rt.Token] = rt
	return nil
}

func (m *MemoryStorage) GetRefreshToken(token string) (RefreshToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.refreshTokens[token]
	return rt, ok, nil
}

func (m *MemoryStorage) DeleteRefreshToken(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, token)
	return nil
}

func (m *MemoryStorage) DeleteRefreshTokensForClient(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for token, rt := range m.refreshTokens {
		if rt.ClientID == clientID {
			delete(m.refreshTokens, token)
		}
	}
	return nil
}

func (m *MemoryStorage) SaveStream(stream Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams[stream.StreamID] = stream
	return nil
}

func (m *MemoryStorage) GetStream(streamID string) (Stream, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.streams[streamID]
	return st, ok, nil
}

func (m *MemoryStorage) ListStreams(clientID string) ([]Stream, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Stream
	for _, st := range m.streams {
		if st.ClientID == clientID {
			out = append(out, st)
		}
	}
	return out, nil
}

func (m *MemoryStorage) DeleteStream(streamID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.streams, streamID)
	delete(m.events, streamID)
	return nil
}

func (m *MemoryStorage) QueueEvent(streamID string, event PendingEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[streamID] = append(m.events[streamID], event)
	return nil
}

func (m *MemoryStorage) PendingEvents(streamID string, max int) ([]PendingEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := m.events[streamID]
	if max > 0 && len(events) > max {
		events = events[:max]
	}
	out := make([]PendingEvent, len(events))
	copy(out, events)
	return out, nil
}

func (m *MemoryStorage) AckEvent(streamID, jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := m.events[streamID]
	for i, e := range events {
		if e.JTI == jti {
			m.events[streamID] = append(events[:i], events[i+1:]...)
			break
		}
	}
	return nil
}
