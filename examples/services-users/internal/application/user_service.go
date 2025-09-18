package application

import (
	"time"

	"github.com/google/uuid"

	"github.com/anasamu/go-micro-libs/examples/services-users/internal/domain"
)

type UserService struct {
	repo domain.UserRepository
	now  func() time.Time
}

func NewUserService(repo domain.UserRepository) *UserService {
	return &UserService{repo: repo, now: time.Now}
}

type CreateUserCommand struct {
	Email string
	Name  string
}

func (s *UserService) CreateUser(cmd CreateUserCommand) (*domain.User, error) {
	if existing, _ := s.repo.GetByEmail(cmd.Email); existing != nil {
		return nil, domain.ErrEmailUsed
	}
	u, err := domain.NewUser(domain.UserID(uuid.NewString()), cmd.Email, cmd.Name, s.now())
	if err != nil {
		return nil, err
	}
	if err := s.repo.Save(u); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *UserService) GetUser(id string) (*domain.User, error) {
	return s.repo.GetByID(domain.UserID(id))
}

func (s *UserService) ListUsers(offset, limit int) ([]*domain.User, error) {
	return s.repo.List(offset, limit)
}

func (s *UserService) DeleteUser(id string) error {
	return s.repo.Delete(domain.UserID(id))
}
