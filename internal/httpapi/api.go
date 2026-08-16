// Package httpapi 提供 Merkle 树构建与校验服务的 HTTP 接口。
// 服务无内部可变状态，可被多个 goroutine 复用。
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"task022-merkle/internal/merkle"
)

// ErrBadJSON 表示请求体不是单个合法 JSON 对象。
var ErrBadJSON = errors.New("请求体不是合法的单个 JSON 对象")

// API 是 Merkle 树服务的 HTTP 接口实现。
type API struct {
	mu    sync.Mutex // 保护 stats，防止并发读写触发 panic
	stats map[string]int // per-endpoint request counts
}

// New 创建服务实例。
func New() *API { return &API{stats: make(map[string]int)} }

// Handler 返回 HTTP 路由。
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /root", a.root)
	mux.HandleFunc("POST /proof", a.proof)
	mux.HandleFunc("POST /verify", a.verify)
	return mux
}

// RequestCount returns how many requests have been served for the given endpoint.
func (a *API) RequestCount(endpoint string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stats[endpoint]
}

// decodeJSON 解码单个 JSON 对象，拒绝多段 JSON 与未知字段。
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return ErrBadJSON
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ErrBadJSON
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.stats["healthz"]++
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// errBody 用于各类 400 错误的统一回应。
type errBody struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// blocksRequest 是根哈希端点的请求体。
type blocksRequest struct {
	Blocks []string `json:"blocks"`
}

// rootResponse 是根哈希端点的回应。
type rootResponse struct {
	Root      string `json:"root"`
	LeafCount int    `json:"leaf_count"`
}

func (a *API) root(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.stats["root"]++
	a.mu.Unlock()
	var req blocksRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{OK: false, Error: err.Error()})
		return
	}
	root, count, err := merkle.Build(req.Blocks)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, rootResponse{Root: root, LeafCount: count})
}

// proofRequest 是证明端点的请求体。
type proofRequest struct {
	Blocks []string `json:"blocks"`
	Index  int      `json:"index"`
}

func (a *API) proof(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.stats["proof"]++
	a.mu.Unlock()
	var req proofRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{OK: false, Error: err.Error()})
		return
	}
	p, _ := merkle.MakeProof(req.Blocks, req.Index)
	if p.Steps == nil {
		p.Steps = []merkle.ProofStep{} // 空证明用 [] 而非 null
	}
	writeJSON(w, http.StatusOK, p)
}

// verifyRequest 是验证端点的请求体。
type verifyRequest struct {
	LeafHash string              `json:"leaf_hash"`
	Steps    []merkle.ProofStep  `json:"steps"`
	Root     string              `json:"root"`
}

// verifyResponse 是验证端点的回应。
type verifyResponse struct {
	Valid bool `json:"valid"`
}

func (a *API) verify(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.stats["verify"]++
	a.mu.Unlock()
	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody{OK: false, Error: err.Error()})
		return
	}
	if req.Steps == nil {
		req.Steps = []merkle.ProofStep{}
	}
	valid, err := merkle.Verify(req.LeafHash, req.Steps, req.Root)
	if err != nil {
		// 格式错误（非法哈希、非法方向）返回 400。
		writeJSON(w, http.StatusBadRequest, errBody{OK: false, Error: err.Error()})
		return
	}
	// 格式正确但证明不成立返回 200 + valid=false。
	writeJSON(w, http.StatusOK, verifyResponse{Valid: valid})
}
