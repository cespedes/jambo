package jambo

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
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
// This only resolves and checks the host once, when the stream is created
// or updated; it is not re-checked before every push, so it does not
// defend against a receiver that DNS-rebinds its endpoint host to a
// private address afterwards.
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

type streamRequest struct {
	StreamID        string   `json:"stream_id,omitempty"`
	Delivery        Delivery `json:"delivery"`
	EventsRequested []string `json:"events_requested"`
	Description     string   `json:"description,omitempty"`
}

func (s *Server) validateDelivery(d Delivery) error {
	switch d.Method {
	case deliveryMethodPush:
		return isSafePushURL(d.EndpointURL, s.allowInsecureSSFPush)
	case deliveryMethodPoll:
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}
	if err := s.validateDelivery(req.Delivery); err != nil {
		s.ssfError(w, http.StatusBadRequest, err)
		return
	}

	stream := Stream{
		StreamID:                rand.Text(),
		Iss:                     s.issuer,
		Aud:                     []string{client.id},
		EventsSupported:         client.ssfEventsSupported,
		EventsRequested:         req.EventsRequested,
		EventsDelivered:         intersect(req.EventsRequested, client.ssfEventsSupported),
		Delivery:                req.Delivery,
		Description:             req.Description,
		MinVerificationInterval: 300,
		ClientID:                client.id,
		Status:                  StreamStatusEnabled,
	}
	if stream.Delivery.Method == deliveryMethodPoll {
		// The transmitter, not the receiver, dictates the poll URL.
		stream.Delivery.EndpointURL = s.issuer + "/ssf/poll/" + stream.StreamID
	}

	if err := s.storage.SaveStream(stream); err != nil {
		http.Error(w, "Internal server error saving stream.", http.StatusInternalServerError)
		return
	}

	s.writeStreamJSON(w, http.StatusCreated, stream)
}

// ssfGetStream handles "GET /ssf/stream". With no stream_id query
// parameter it lists every stream belonging to the caller's client.
func (s *Server) ssfGetStream(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage", "ssf.read")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}

	if streamID := r.URL.Query().Get("stream_id"); streamID != "" {
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
		return
	}

	streams, err := s.storage.ListStreams(clientID)
	if err != nil {
		http.Error(w, "Internal server error listing streams.", http.StatusInternalServerError)
		return
	}
	// The spec is not precise about the envelope for a multi-stream listing
	// (a real receiver such as Apple Business Manager is expected to always
	// know its own stream_id and use the single-stream path above); this
	// array-under-"streams" shape is Jambo's own choice.
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string][]Stream{"streams": streams}); err != nil {
		http.Error(w, "Internal server error marshaling streams.", http.StatusInternalServerError)
	}
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		if stream.Delivery.Method == deliveryMethodPoll {
			stream.Delivery.EndpointURL = s.issuer + "/ssf/poll/" + stream.StreamID
		}
	}
	if replace || req.EventsRequested != nil {
		stream.EventsRequested = req.EventsRequested
		stream.EventsDelivered = intersect(req.EventsRequested, stream.EventsSupported)
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

// ssfDeleteStream handles "DELETE /ssf/stream?stream_id=...".
func (s *Server) ssfDeleteStream(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	streamID := r.URL.Query().Get("stream_id")
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

// ssfGetStatus handles "GET /ssf/status?stream_id=...".
func (s *Server) ssfGetStatus(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage", "ssf.read")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	streamID := r.URL.Query().Get("stream_id")
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}
	if body.Status != StreamStatusEnabled && body.Status != StreamStatusPaused && body.Status != StreamStatusDisabled {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("invalid status %q", body.Status))
		return
	}
	stream, ok, err := s.storage.GetStream(body.StreamID)
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

// ssfAddSubject handles "POST /ssf/subjects:add".
func (s *Server) ssfAddSubject(w http.ResponseWriter, r *http.Request) {
	clientID, err := s.requireSSFScope(r, "ssf.manage")
	if err != nil {
		s.ssfError(w, http.StatusUnauthorized, err)
		return
	}
	var req subjectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.ssfError(w, http.StatusBadRequest, fmt.Errorf("malformed JSON body: %w", err))
		return
	}
	stream, ok, err := s.storage.GetStream(body.StreamID)
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
