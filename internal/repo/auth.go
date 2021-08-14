package repo

import (
	"database/sql"
	"time"

	"github.com/danisbagus/semimarket-auth/internal/core/domain"
	"github.com/danisbagus/semimarket-auth/internal/core/port"
	"github.com/danisbagus/semimarket-auth/pkg/errs"
	"github.com/danisbagus/semimarket-auth/pkg/logger"

	"github.com/jmoiron/sqlx"
)

const ACCESS_TOKEN_DURATION = time.Hour

type AuthRepo struct {
	db *sqlx.DB
}

func NewAuthRepo(db *sqlx.DB) port.IAuthRepo {
	return &AuthRepo{
		db: db,
	}
}

func (r AuthRepo) FindOne(username string, password string) (*domain.Login, *errs.AppError) {
	var login domain.Login
	sqlVerify := `select user_id, username, role, created_on from users where username = ? and password = ?`

	err := r.db.Get(&login, sqlVerify, username, password)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errs.NewAuthenticationError("invalid credentials")
		} else {
			logger.Error("Error while verifying login request from database: " + err.Error())
			return nil, errs.NewUnexpectedError("Unexpected database error")
		}
	}
	return &login, nil
}
