package infrastructure

import (
	"context"
	"time"

	libdb "github.com/anasamu/go-micro-libs/database"
	"github.com/anasamu/go-micro-libs/examples/services-users/internal/domain"
)

type SQLUserRepository struct {
	db           *libdb.DatabaseManager
	providerName string
}

func NewSQLUserRepository(db *libdb.DatabaseManager, providerName string) *SQLUserRepository {
	return &SQLUserRepository{db: db, providerName: providerName}
}

func (r *SQLUserRepository) Save(u *domain.User) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// upsert by email unique
	_, err := r.db.Exec(ctx, r.providerName,
		`INSERT INTO users (id, email, name, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (email)
         DO UPDATE SET name = EXCLUDED.name, updated_at = EXCLUDED.updated_at`,
		string(u.ID), u.Email, u.Name, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		return err
	}
	return nil
}

func (r *SQLUserRepository) GetByID(id domain.UserID) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	row, err := r.db.QueryRow(ctx, r.providerName,
		`SELECT id, email, name, created_at, updated_at FROM users WHERE id = $1`, string(id))
	if err != nil {
		return nil, err
	}
	var u domain.User
	var idStr string
	if err := row.Scan(&idStr, &u.Email, &u.Name, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, domain.ErrUserNotFound
	}
	u.ID = domain.UserID(idStr)
	return &u, nil
}

func (r *SQLUserRepository) GetByEmail(email string) (*domain.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	row, err := r.db.QueryRow(ctx, r.providerName,
		`SELECT id, email, name, created_at, updated_at FROM users WHERE email = $1`, email)
	if err != nil {
		return nil, err
	}
	var u domain.User
	var idStr string
	if err := row.Scan(&idStr, &u.Email, &u.Name, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, domain.ErrUserNotFound
	}
	u.ID = domain.UserID(idStr)
	return &u, nil
}

func (r *SQLUserRepository) List(offset, limit int) ([]*domain.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// basic pagination
	rows, err := r.db.Query(ctx, r.providerName,
		`SELECT id, email, name, created_at, updated_at
         FROM users
         ORDER BY created_at DESC
         OFFSET $1 LIMIT $2`, offset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*domain.User
	for rows.Next() {
		var u domain.User
		var idStr string
		if err := rows.Scan(&idStr, &u.Email, &u.Name, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		u.ID = domain.UserID(idStr)
		users = append(users, &u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (r *SQLUserRepository) Delete(id domain.UserID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := r.db.Exec(ctx, r.providerName, `DELETE FROM users WHERE id = $1`, string(id))
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return domain.ErrUserNotFound
	}
	return nil
}
