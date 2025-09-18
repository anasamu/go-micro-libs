package domain

import (
	"errors"
	"time"
)

var (
	ErrUserNotFound = errors.New("user not found")
	ErrEmailUsed    = errors.New("email already used")
)

type UserID string

type User struct {
	ID        UserID
	Email     string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewUser(id UserID, email, name string, now time.Time) (*User, error) {
	if email == "" || name == "" {
		return nil, errors.New("invalid user data")
	}
	return &User{
		ID:        id,
		Email:     email,
		Name:      name,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

type UserRepository interface {
	Save(u *User) error
	GetByID(id UserID) (*User, error)
	GetByEmail(email string) (*User, error)
	List(offset, limit int) ([]*User, error)
	Delete(id UserID) error
}
