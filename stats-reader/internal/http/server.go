// Package httpsrv serves the public stats endpoints: a store-backed
// snapshot with a strict key allowlist, plus always-on readiness probes.
package httpsrv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

// SnapshotStore supplies validated snapshot bytes and store health.
type SnapshotStore interface {
	Snapshot(ctx context.Context) ([]byte, error)
	Health(ctx context.Context) (redisOK, minioOK bool)
}

const (
	unavailableBody = `{"error":"Metrics unavailable"}`
	healthTimeout   = 2 * time.Second
)

// Top-level snapshot v2 allowlist. Unknown keys are stripped before emit.
var topLevelKeys = []string{
	"asOf",
	"peaksComputedAt",
	"peakRecordsDay",
	"peakRecordsDayDate",
	"peakRecordsWeek",
	"peakRecordsWeekStart",
	"peakRecordsWeekEnd",
	"liveStrip",
	"lifetimeTotals",
	"throughput24h",
	"throughput7d",
}

var liveStripKeys = []string{
	"ingestProcessedRatePerSec",
	"pendingLedgerCount",
	"brokerLagCount",
	"lastIngestSuccessAt",
	"backpressureActive",
}

var lifetimeTotalsKeys = []string{
	"recordsTotal",
	"daysCounted",
	"computedAt",
}

var throughputKeys = []string{
	"bucket",
	"series",
}

var seriesItemKeys = []string{
	"bucketStart",
	"records",
}

// Server routes public stats, readiness, and operator health.
type Server struct {
	store   SnapshotStore
	origins map[string]struct{}
	mux     *http.ServeMux
}

// New builds the handler set. allowedOrigins is the CORS allowlist.
func New(store SnapshotStore, allowedOrigins []string) *Server {
	s := &Server{
		store:   store,
		origins: make(map[string]struct{}, len(allowedOrigins)),
		mux:     http.NewServeMux(),
	}
	for _, o := range allowedOrigins {
		if o != "" {
			s.origins[o] = struct{}{}
		}
	}
	s.mux.HandleFunc("GET /public/stats", s.handleStats)
	s.mux.HandleFunc("OPTIONS /public/stats", s.handlePreflight)
	s.mux.HandleFunc("GET /ready", s.handleReady)
	s.mux.HandleFunc("GET /live", s.handleLive)
	s.mux.HandleFunc("GET /health", s.handleHealth)
	return s
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.applyCORS(w, r)
	w.Header().Set("Cache-Control", "public, max-age=30")
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Content-Type", "application/json")

	raw, err := s.store.Snapshot(r.Context())
	if err != nil {
		writeUnavailable(w)
		return
	}
	out, err := sanitizeSnapshot(raw)
	if err != nil {
		writeUnavailable(w)
		return
	}
	_, _ = w.Write(out)
}

func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	allowed := s.applyCORS(w, r)
	w.Header().Set("Vary", "Origin")
	if allowed {
		w.Header().Set("Access-Control-Max-Age", "600")
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleReady is always 200 once the process is up. Store health never
// gates readiness, so Traefik keeps routing to this service.
func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok"))
}

// handleHealth reports store reachability for operators. Traefik does
// not use it.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), healthTimeout)
	defer cancel()
	redisOK, minioOK := s.store.Health(ctx)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{
		"redis": redisOK,
		"minio": minioOK,
	})
}

func writeUnavailable(w http.ResponseWriter) {
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(unavailableBody))
}

// applyCORS sets CORS headers when the request Origin is allowlisted and
// reports whether it was.
func (s *Server) applyCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	if _, ok := s.origins[origin]; !ok {
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type")
	return true
}

// sanitizeSnapshot keeps only allowlisted keys and requires asOf. Keys
// that are absent stay absent; values are never invented.
func sanitizeSnapshot(raw []byte) ([]byte, error) {
	var top map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&top); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("snapshot contains trailing data")
	}
	out := make(map[string]any, len(topLevelKeys))
	for _, k := range topLevelKeys {
		v, ok := top[k]
		if !ok {
			continue
		}
		switch k {
		case "liveStrip":
			if filtered, ok := filterObject(v, liveStripKeys); ok {
				out[k] = filtered
			}
		case "lifetimeTotals":
			if filtered, ok := filterObject(v, lifetimeTotalsKeys); ok {
				out[k] = filtered
			}
		case "throughput24h", "throughput7d":
			if filtered, ok := filterThroughput(v); ok {
				out[k] = filtered
			}
		default:
			if validLeaf(k, v) {
				out[k] = v
			}
		}
	}
	asOf, ok := out["asOf"].(string)
	if !ok || asOf == "" {
		return nil, errors.New("snapshot missing asOf")
	}
	return json.Marshal(out)
}

// filterObject keeps allowlisted, correctly typed fields and preserves null.
func filterObject(v any, allowed []string) (any, bool) {
	if v == nil {
		return nil, true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(allowed))
	for _, k := range allowed {
		if nv, ok := m[k]; ok && validLeaf(k, nv) {
			out[k] = nv
		}
	}
	return out, true
}

func validLeaf(key string, v any) bool {
	if v == nil {
		return true
	}
	switch key {
	case "asOf", "peaksComputedAt", "peakRecordsDayDate", "peakRecordsWeekStart",
		"peakRecordsWeekEnd", "lastIngestSuccessAt", "computedAt", "bucket", "bucketStart":
		_, ok := v.(string)
		return ok
	case "backpressureActive":
		_, ok := v.(bool)
		return ok
	default:
		_, ok := v.(json.Number)
		return ok
	}
}

func filterThroughput(v any) (any, bool) {
	if v == nil {
		return nil, true
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	out := make(map[string]any, len(throughputKeys))
	for _, k := range throughputKeys {
		nv, ok := m[k]
		if !ok {
			continue
		}
		if k == "series" {
			if series, ok := filterSeries(nv); ok {
				out[k] = series
			}
			continue
		}
		if validLeaf(k, nv) {
			out[k] = nv
		}
	}
	return out, true
}

func filterSeries(v any) (any, bool) {
	if v == nil {
		return nil, true
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]any, 0, len(arr))
	for _, item := range arr {
		if filtered, ok := filterObject(item, seriesItemKeys); ok {
			out = append(out, filtered)
		}
	}
	return out, true
}
