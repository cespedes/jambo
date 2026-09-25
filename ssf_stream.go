package jambo

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
)

// isSafePushURL rejects push delivery endpoints that would make the
// transmitter issue HTTP requests to loopback, private or link-local
// addresses -- i.e. a basic SSRF guard against a receiver registering an
// internal URL as its push endpoint. Server.SetSSFAllowPrivatePush(true)
// disables this check, for local development and tests.
//
// It is called here, when the stream is created or updated, and again by
// pushEvent before every delivery attempt, so a receiver that DNS-rebinds
// its endpoint host to a private address after registering it still gets
// rejected the next time an event is actually pushed. A malicious
// redirect from the endpoint itself is a separate concern, guarded
// against by pushEvent's client refusing to follow redirects at all.
func isSafePushURL(rawURL string, allowPrivate bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid endpoint_url: %w", err)
	}
	if allowPrivate {
		return nil
	}
	if u.Scheme != "https" {
		return fmt.Errorf("endpoint_url must use https")
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return fmt.Errorf("cannot resolve endpoint_url host: %w", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("endpoint_url resolves to a non-public address")
		}
	}
	return nil
}

// intersect returns the elements of a that are also present in b, in a's order.
func intersect(a, b []string) []string {
	var out []string
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// ensureVerificationEvent returns eventTypes with eventSSFVerification
// appended, unless it's already present.
func ensureVerificationEvent(eventTypes []string) []string {
	if slices.Contains(eventTypes, eventSSFVerification) {
		return eventTypes
	}
	return append(append([]string{}, eventTypes...), eventSSFVerification)
}

type streamRequest struct {
	StreamID        string       `json:"stream_id,omitempty"`
	Aud             audienceList `json:"aud,omitempty"`
	Delivery        Delivery     `json:"delivery"`
	EventsRequested []string     `json:"events_requested"`
	Description     string       `json:"description,omitempty"`
	Format          string       `json:"format,omitempty"`
}

// streamIDFromRequest returns "stream_id" from the query string
// (?stream_id=...) if present, falling back to a JSON request body
// {"stream_id": "..."}: some receivers (Apple Business Manager, observed
// on DELETE) send it there instead, even for methods that would
// conventionally use a query parameter.
func (s *Server) streamIDFromRequest(r *http.Request) string {
	if id := r.URL.Query().Get("stream_id"); id != "" {
		return id
	}
	var body struct {
		StreamID string `json:"stream_id"`
	}
	_ = s.decodeSSFJSON(r, &body)
	return body.StreamID
}

// soleStreamForClient returns clientID's only stream, if it has exactly
// one. Some receivers (Apple Business Manager, observed on DELETE) send
// no stream identifier at all on GET/DELETE calls, relying on the
// invariant -- true for a receiver like it, which manages a single
// stream -- that there's exactly one stream to act on.
func (s *Server) soleStreamForClient(clientID string) (Stream, bool, error) {
	streams, err := s.storage.ListStreams(clientID)
	if err != nil {
		return Stream{}, false, err
	}
	if len(streams) != 1 {
		return Stream{}, false, nil
	}
	return streams[0], true, nil
}

// resolveStreamID returns streamID (typically already read from a decoded
// JSON body) if non-empty, otherwise falls back to the ?stream_id= query
// parameter and finally to soleStreamForClient. badRequest is non-nil
// exactly when no stream could be identified at all -- callers should
// report that as a 400; err is non-nil only on a genuine storage failure
// and should be reported as a 500.
//
// Callers that need other fields from the same JSON body must decode it
// themselves and pass the resulting stream_id in, rather than have this
// read the body again: an http.Request's body can only be read once.
func (s *Server) resolveStreamID(r *http.Request, clientID, streamID string) (id string, badRequest, err error) {
	if streamID == "" {
		streamID = r.URL.Query().Get("stream_id")
	}
	if streamID != "" {
		return streamID, nil, nil
	}
	sole, ok, err := s.soleStreamForClient(clientID)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		return "", fmt.Errorf("stream_id is required (client has zero or multiple streams)"), nil
	}
	return sole.StreamID, nil, nil
}

func (s *Server) validateDelivery(d Delivery) error {
	switch {
	case isPushDeliveryMethod(d.Method):
		return isSafePushURL(d.EndpointURL, s.allowInsecureSSFPush)
	case isPollDeliveryMethod(d.Method):
		return nil
	default:
		return fmt.Errorf("unsupported delivery method %q", d.Method)
	}
}

// ssfCreateStream handles "POST /ssf/stream".
func (s *Server) ssfCreateStream(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	client := s.clientByID(clientID)

	var req streamRequest
	if err := s.decodeSSFJSON(r, &req); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}
	if err := s.validateDelivery(req.Delivery); err != nil {
		s.ssfError(w, http.StatusBadRequest, err)
		return
	}

	// "aud" identifies the receiver, not the OAuth client: a receiver like
	// Apple Business Manager sets it to its own feed URL, not to its
	// client_id, so it can recognize SETs addressed to it. Honor whatever
	// the (already-authenticated) receiver asked for, falling back to the
	// client ID only if it didn't send one.
	aud := []string(req.Aud)
	if len(aud) == 0 {
		aud = []string{client.id}
	}

	// Every stream supports the built-in verification event, whether or
	// not the receiver asked for it: real receivers (Apple Business
	// Manager, confirmed against authentik's working SSF transmitter)
	// expect it in events_requested/events_supported unconditionally.
	eventsRequested := ensureVerificationEvent(req.EventsRequested)
	eventsSupported := ensureVerificationEvent(client.ssfEventsSupported)

	stream := Stream{
		StreamID:                rand.Text(),
		Iss:                     s.issuer,
		Aud:                     aud,
		EventsSupported:         eventsSupported,
		EventsRequested:         eventsRequested,
		EventsDelivered:         intersect(eventsRequested, eventsSupported),
		Delivery:                req.Delivery,
		Description:             req.Description,
		Format:                  req.Format,
		MinVerificationInterval: 300,
		ClientID:                client.id,
		Status:                  StreamStatusEnabled,
	}
	if isPollDeliveryMethod(stream.Delivery.Method) {
		// The transmitter, not the receiver, dictates the poll URL.
		stream.Delivery.EndpointURL = s.issuer + "/ssf/poll/" + stream.StreamID
	}

	if err := s.storage.SaveStream(stream); err != nil {
		http.Error(w, "Internal server error saving stream.", http.StatusInternalServerError)
		return
	}

	if s.debug {
		log.Printf("SSF: created stream %s for client %s (delivery=%s, events_requested=%v, events_delivered=%v)\n",
			stream.StreamID, client.id, stream.Delivery.Method, stream.EventsRequested, stream.EventsDelivered)
	}

	// Proactively push a verification SET right after creation, without
	// waiting for the receiver to call /ssf/verify: this is what a real
	// receiver (observed: Apple Business Manager) actually waits on to
	// consider the stream successfully set up, per authentik's transmitter.
	if err := s.deliverEvent(stream, eventSSFVerification, Subject{Format: SubjectFormatOpaque, ID: stream.StreamID}, nil); err != nil && s.debug {
		log.Printf("SSF: failed to send initial verification event for stream %s: %v\n", stream.StreamID, err)
	}
	s.writeStreamJSON(w, http.StatusCreated, stream)
}

// ssfGetStream handles "GET /ssf/stream". With no stream_id given, it
// returns the caller's one stream if it has exactly one (some receivers,
// e.g. Apple Business Manager, rely on that instead of naming it), or
// otherwise lists every stream belonging to the caller's client.
func (s *Server) ssfGetStream(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage", "ssf.read")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}

	streamID := s.streamIDFromRequest(r)
	if streamID == "" {
		if sole, ok, err := s.soleStreamForClient(clientID); err != nil {
			http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
			return
		} else if ok {
			s.writeStreamJSON(w, http.StatusOK, sole)
			return
		}

		streams, err := s.storage.ListStreams(clientID)
		if err != nil {
			http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
			return
		}
		// The spec is not precise about the envelope for a multi-stream
		// listing; this array-under-"streams" shape is Jambo's own choice.
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string][]Stream{"streams": streams}); err != nil {
			http.Error(w, "Internal server error marshaling streams.", http.StatusInternalServerError)
		}
		return
	}

	stream, ok, err := s.storage.GetStream(streamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}
	s.writeStreamJSON(w, http.StatusOK, stream)
}

// ssfUpdateStream handles "PATCH /ssf/stream": only fields present in the
// request body are changed.
func (s *Server) ssfUpdateStream(w http.ResponseWriter, r *http.Request) {
	s.ssfModifyStream(w, r, false)
}

// ssfReplaceStream handles "PUT /ssf/stream": events_requested and
// delivery are required and fully replace the existing configuration.
func (s *Server) ssfReplaceStream(w http.ResponseWriter, r *http.Request) {
	s.ssfModifyStream(w, r, true)
}

func (s *Server) ssfModifyStream(w http.ResponseWriter, r *http.Request, replace bool) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}

	var req streamRequest
	if err := s.decodeSSFJSON(r, &req); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}
	if req.StreamID == "" {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("stream_id is required"))
		return
	}
	stream, ok, err := s.storage.GetStream(req.StreamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}

	if replace || req.Delivery.Method != "" {
		if err := s.validateDelivery(req.Delivery); err != nil {
			s.ssfError(w, http.StatusBadRequest, err)
			return
		}
		stream.Delivery = req.Delivery
		if isPollDeliveryMethod(stream.Delivery.Method) {
			stream.Delivery.EndpointURL = s.issuer + "/ssf/poll/" + stream.StreamID
		}
	}
	if replace || len(req.Aud) > 0 {
		stream.Aud = req.Aud
	}
	if replace || req.EventsRequested != nil {
		stream.EventsRequested = ensureVerificationEvent(req.EventsRequested)
		stream.EventsDelivered = intersect(stream.EventsRequested, stream.EventsSupported)
	}
	if replace || req.Description != "" {
		stream.Description = req.Description
	}

	if err := s.storage.SaveStream(stream); err != nil {
		http.Error(w, "Internal server error saving stream.", http.StatusInternalServerError)
		return
	}

	s.emitStreamUpdated(stream)
	s.writeStreamJSON(w, http.StatusOK, stream)
}

// ssfDeleteStream handles "DELETE /ssf/stream", identifying the stream
// via ?stream_id=..., a {"stream_id": "..."} JSON body, or -- if neither
// is given and the caller's client has exactly one stream, as observed
// with Apple Business Manager -- that one stream.
func (s *Server) ssfDeleteStream(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	streamID, badRequest, err := s.resolveStreamID(r, clientID, s.streamIDFromRequest(r))
	if err != nil {
		http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
		return
	}
	if badRequest != nil {
		s.ssfError(w, http.StatusBadRequest, badRequest)
		return
	}
	stream, ok, err := s.storage.GetStream(streamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}
	if err := s.storage.DeleteStream(streamID); err != nil {
		http.Error(w, "Internal server error deleting stream.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ssfGetStatus handles "GET /ssf/status", identifying the stream via
// ?stream_id=..., a {"stream_id": "..."} JSON body, or -- if neither is
// given and the caller's client has exactly one stream -- that one stream.
func (s *Server) ssfGetStatus(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage", "ssf.read")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	streamID, badRequest, err := s.resolveStreamID(r, clientID, s.streamIDFromRequest(r))
	if err != nil {
		http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
		return
	}
	if badRequest != nil {
		s.ssfError(w, http.StatusBadRequest, badRequest)
		return
	}
	stream, ok, err := s.storage.GetStream(streamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"stream_id": stream.StreamID, "status": stream.Status})
}

// ssfSetStatus handles "POST /ssf/status".
func (s *Server) ssfSetStatus(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	var body struct {
		StreamID string `json:"stream_id"`
		Status   string `json:"status"`
	}
	if err := s.decodeSSFJSON(r, &body); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}
	if body.Status != StreamStatusEnabled && body.Status != StreamStatusPaused && body.Status != StreamStatusDisabled {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("invalid status %q", body.Status))
		return
	}
	streamID, badRequest, err := s.resolveStreamID(r, clientID, body.StreamID)
	if err != nil {
		http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
		return
	}
	if badRequest != nil {
		s.ssfError(w, http.StatusBadRequest, badRequest)
		return
	}
	stream, ok, err := s.storage.GetStream(streamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}
	stream.Status = body.Status
	if err := s.storage.SaveStream(stream); err != nil {
		http.Error(w, "Internal server error saving stream.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"stream_id": stream.StreamID, "status": stream.Status})
}

type subjectRequest struct {
	StreamID string  `json:"stream_id"`
	Subject  Subject `json:"subject"`
}

// ssfAddSubject handles "POST /ssf/subjects:add". It does not check that
// req.Subject has any actual relationship to the calling client (e.g. has
// ever authenticated through it) -- see the README's "Trust model for
// /ssf/subjects:add" section. A host application that needs to prevent a
// client from registering an unrelated subject must enforce that itself.
func (s *Server) ssfAddSubject(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	var req subjectRequest
	if err := s.decodeSSFJSON(r, &req); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}
	streamID, badRequest, err := s.resolveStreamID(r, clientID, req.StreamID)
	if err != nil {
		http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
		return
	}
	if badRequest != nil {
		s.ssfError(w, http.StatusBadRequest, badRequest)
		return
	}
	stream, ok, err := s.storage.GetStream(streamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}
	if !slices.ContainsFunc(stream.Subjects, req.Subject.equal) {
		stream.Subjects = append(stream.Subjects, req.Subject)
		if err := s.storage.SaveStream(stream); err != nil {
			http.Error(w, "Internal server error saving stream.", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ssfRemoveSubject handles "POST /ssf/subjects:remove".
func (s *Server) ssfRemoveSubject(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	var req subjectRequest
	if err := s.decodeSSFJSON(r, &req); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}
	streamID, badRequest, err := s.resolveStreamID(r, clientID, req.StreamID)
	if err != nil {
		http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
		return
	}
	if badRequest != nil {
		s.ssfError(w, http.StatusBadRequest, badRequest)
		return
	}
	stream, ok, err := s.storage.GetStream(streamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}
	stream.Subjects = slices.DeleteFunc(stream.Subjects, req.Subject.equal)
	if err := s.storage.SaveStream(stream); err != nil {
		http.Error(w, "Internal server error saving stream.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ssfVerify handles "POST /ssf/verify": it makes the transmitter emit a
// "verification" lifecycle event through the stream, so the receiver can
// confirm the stream is alive end-to-end.
func (s *Server) ssfVerify(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	var body struct {
		StreamID string `json:"stream_id"`
		State    string `json:"state,omitempty"`
	}
	if err := s.decodeSSFJSON(r, &body); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}

	streamID, badRequest, err := s.resolveStreamID(r, clientID, body.StreamID)
	if err != nil {
		http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
		return
	}
	if badRequest != nil {
		s.ssfError(w, http.StatusBadRequest, badRequest)
		return
	}

	stream, ok, err := s.storage.GetStream(streamID)
	if err != nil {
		http.Error(w, "Internal server error reading stream.", http.StatusInternalServerError)
		return
	}
	if !ok || stream.ClientID != clientID {
		s.ssfError(w, http.StatusNotFound, fmt.Errorf("unknown stream_id"))
		return
	}

	claims := map[string]any{}
	if body.State != "" {
		claims["state"] = body.State
	}
	if err := s.deliverEvent(stream, eventSSFVerification, Subject{Format: SubjectFormatOpaque, ID: stream.StreamID}, claims); err != nil {
		http.Error(w, "Internal server error signing verification event.", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) emitStreamUpdated(stream Stream) {
	_ = s.deliverEvent(stream, eventSSFStreamUpdated, Subject{Format: SubjectFormatOpaque, ID: stream.StreamID}, nil)
}

func (s *Server) writeStreamJSON(w http.ResponseWriter, status int, stream Stream) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(stream)
}
