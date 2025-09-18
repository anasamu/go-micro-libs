package infrastructure

import (
	"sync"

	"github.com/anasamu/go-micro-libs/examples/services-users/internal/domain"
)

type MemoryUserRepository struct {
	byID    map[domain.UserID]*domain.User
	byEmail map[string]domain.UserID
	mu      sync.RWMutex
}

func NewMemoryUserRepository() *MemoryUserRepository {
	return &MemoryUserRepository{
		byID:    make(map[domain.UserID]*domain.User),
		byEmail: make(map[string]domain.UserID),
	}
}

func (r *MemoryUserRepository) Save(u *domain.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existingID, ok := r.byEmail[u.Email]; ok && existingID != u.ID {
		return domain.ErrEmailUsed
	}
	r.byID[u.ID] = u
	r.byEmail[u.Email] = u.ID
	return nil
}

func (r *MemoryUserRepository) GetByID(id domain.UserID) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if u, ok := r.byID[id]; ok {
		return u, nil
	}
	return nil, domain.ErrUserNotFound
}

func (r *MemoryUserRepository) GetByEmail(email string) (*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if id, ok := r.byEmail[email]; ok {
		if u, ok2 := r.byID[id]; ok2 {
			return u, nil
		}
	}
	return nil, domain.ErrUserNotFound
}

func (r *MemoryUserRepository) List(offset, limit int) ([]*domain.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	users := make([]*domain.User, 0, len(r.byID))
	for _, u := range r.byID {
		users = append(users, u)
	}
	if offset >= len(users) {
		return []*domain.User{}, nil
	}
	end := offset + limit
	if end > len(users) {
		end = len(users)
	}
	return users[offset:end], nil
}

func (r *MemoryUserRepository) Delete(id domain.UserID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.byID[id]
	if !ok {
		return domain.ErrUserNotFound
	}
	delete(r.byID, id)
	delete(r.byEmail, u.Email)
	return nil
}
