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
	// SaveRefreshToken creates or overwrites a refresh token, keyed by rt.Token.
	SaveRefreshToken(rt RefreshToken) error
	// GetRefreshToken looks up a previously saved refresh token by its value.
	GetRefreshToken(token string) (rt RefreshToken, ok bool, err error)
	// DeleteRefreshToken removes one refresh token. Deleting an unknown
	// token is a no-op.
	DeleteRefreshToken(token string) error
	// DeleteRefreshTokensForClient removes every refresh token issued to
	// clientID. Server.RemoveClient calls this, so a client id that gets
	// reused later (e.g. NewClient after RemoveClient) never silently
	// inherits tokens issued to whatever previously had that id.
	DeleteRefreshTokensForClient(clientID string) error

	// SaveStream creates or overwrites a stream, keyed by stream.StreamID.
	SaveStream(stream Stream) error
	// GetStream looks up a previously saved stream by its id.
	GetStream(streamID string) (stream Stream, ok bool, err error)
	// ListStreams returns every stream belonging to clientID.
	ListStreams(clientID string) ([]Stream, error)
	// DeleteStream removes one stream and any events queued for it.
	// Deleting an unknown stream id is a no-op.
	DeleteStream(streamID string) error

	// QueueEvent appends a signed Security Event Token pending poll delivery.
	QueueEvent(streamID string, event PendingEvent) error
	// PendingEvents returns up to max not-yet-acknowledged events for
	// streamID, oldest first, and whether more remain beyond those
	// returned. A max <= 0 means "no limit" (moreAvailable is then always false).
	PendingEvents(streamID string, max int) (events []PendingEvent, moreAvailable bool, err error)
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

// NewMemoryStorage returns an empty [MemoryStorage], ready to use.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		refreshTokens: make(map[string]RefreshToken),
		streams:       make(map[string]Stream),
		events:        make(map[string][]PendingEvent),
	}
}

// SaveRefreshToken implements [Storage].
func (m *MemoryStorage) SaveRefreshToken(rt RefreshToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshTokens[rt.Token] = rt
	return nil
}

// GetRefreshToken implements [Storage].
func (m *MemoryStorage) GetRefreshToken(token string) (RefreshToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.refreshTokens[token]
	return rt, ok, nil
}

// DeleteRefreshToken implements [Storage].
func (m *MemoryStorage) DeleteRefreshToken(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.refreshTokens, token)
	return nil
}

// DeleteRefreshTokensForClient implements [Storage].
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

// SaveStream implements [Storage].
func (m *MemoryStorage) SaveStream(stream Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streams[stream.StreamID] = stream
	return nil
}

// GetStream implements [Storage].
func (m *MemoryStorage) GetStream(streamID string) (Stream, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.streams[streamID]
	return st, ok, nil
}

// ListStreams implements [Storage].
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

// DeleteStream implements [Storage].
func (m *MemoryStorage) DeleteStream(streamID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.streams, streamID)
	delete(m.events, streamID)
	return nil
}

// QueueEvent implements [Storage].
func (m *MemoryStorage) QueueEvent(streamID string, event PendingEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events[streamID] = append(m.events[streamID], event)
	return nil
}

// PendingEvents implements [Storage].
func (m *MemoryStorage) PendingEvents(streamID string, max int) ([]PendingEvent, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	events := m.events[streamID]
	var moreAvailable bool
	if max > 0 && len(events) > max {
		moreAvailable = true
		events = events[:max]
	}
	out := make([]PendingEvent, len(events))
	copy(out, events)
	return out, moreAvailable, nil
}

// AckEvent implements [Storage].
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
