package http

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	micro "github.com/anasamu/go-micro-libs"
	rltypes "github.com/anasamu/go-micro-libs/ratelimit/types"

	"github.com/anasamu/go-micro-libs/examples/services-users/internal/application"
	"github.com/anasamu/go-micro-libs/examples/services-users/internal/domain"
)

type UserHandlers struct {
	svc *application.UserService
	// optional cross-cutting tools
	RateLimiter *micro.RateLimitManager
	RateLimit   *rltypes.RateLimit
	Circuit     *micro.CircuitBreakerManager
	CircuitName string
}

func NewUserHandlers(svc *application.UserService) *UserHandlers {
	return &UserHandlers{svc: svc}
}

func (h *UserHandlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("/users", h.HandleUsers)
	mux.HandleFunc("/users/", h.HandleUserByID)
}

func (h *UserHandlers) HandleUsers(w http.ResponseWriter, r *http.Request) {
	// simple rate limit example per IP
	if h.RateLimiter != nil && h.RateLimit != nil {
		key := "rl:" + r.RemoteAddr
		if res, err := h.RateLimiter.Allow(r.Context(), key, h.RateLimit); err == nil && !res.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter/time.Second)))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
	}
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		u, err := h.svc.CreateUser(application.CreateUserCommand{Email: body.Email, Name: body.Name})
		if err != nil {
			status := http.StatusInternalServerError
			if err == domain.ErrEmailUsed {
				status = http.StatusConflict
			}
			http.Error(w, err.Error(), status)
			return
		}
		writeJSON(w, http.StatusCreated, u)
	case http.MethodGet:
		q := r.URL.Query()
		offset, _ := strconv.Atoi(q.Get("offset"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		if limit <= 0 {
			limit = 50
		}
		var users []*domain.User
		var err error
		if h.Circuit != nil && h.CircuitName != "" {
			// wrap list with circuit breaker
			_, err = h.Circuit.Execute(r.Context(), h.CircuitName, func() (interface{}, error) {
				us, e := h.svc.ListUsers(offset, limit)
				users = us
				return nil, e
			})
		} else {
			users, err = h.svc.ListUsers(offset, limit)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, users)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *UserHandlers) HandleUserByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/users/"):]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, err := h.svc.GetUser(id)
		if err != nil {
			status := http.StatusInternalServerError
			if err == domain.ErrUserNotFound {
				status = http.StatusNotFound
			}
			http.Error(w, err.Error(), status)
			return
		}
		writeJSON(w, http.StatusOK, u)
	case http.MethodDelete:
		if err := h.svc.DeleteUser(id); err != nil {
			status := http.StatusInternalServerError
			if err == domain.ErrUserNotFound {
				status = http.StatusNotFound
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
