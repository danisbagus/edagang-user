package repo

import (
	"database/sql"
	"strings"
	"time"

	"github.com/danisbagus/edagang-pkg/errs"
	"github.com/danisbagus/edagang-pkg/logger"
	"github.com/danisbagus/edagang-user/internal/core/domain"
	"github.com/danisbagus/edagang-user/internal/core/port"

	"github.com/jmoiron/sqlx"
)

const ACCESS_TOKEN_DURATION = time.Hour

var RolePermissionsList = map[string][]string{
	"admin": {"GetProductList", "GetProductDetail", "NewProduct", "NewTransaction", "RemoveProduct", "UpdateProduct"},
	"user":  {"GetProductList", "GetProductDetail", "NewTransaction"},
}

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

func (r AuthRepo) VerifyAuthorization(role string, routeName string) bool {
	perms := RolePermissionsList[role]
	for _, r := range perms {
		if r == strings.TrimSpace(routeName) {
			return true
		}
	}
	return false

}

func (r AuthRepo) GenerateAndSaveRefreshTokenStore(authToken domain.AuthToken) (string, *errs.AppError) {
	// Generate refresh token
	var refreshToken string
	var appErr *errs.AppError
	if refreshToken, appErr = authToken.NewRefreshToken(); appErr != nil {
		return "", appErr
	}

	// Store it in the store
	sqlInsert := "insert into refresh_token_store (refresh_token) values (?)"
	_, err := r.db.Exec(sqlInsert, refreshToken)
	if err != nil {
		logger.Error("Unexpected database error: " + err.Error())
		return "", errs.NewUnexpectedError("Unexpected database error")
	}

	return refreshToken, nil
}

func (r AuthRepo) RefreshTokenExists(refreshToken string) *errs.AppError {
	sqlSelect := "select refresh_token from refresh_token_store where refresh_token = ?"

	var token string

	err := r.db.Get(&token, sqlSelect, refreshToken)
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Error("Refresh token not registered in the store")
			return errs.NewAuthenticationError("Refresh token not registered in the store")
		} else {
			logger.Error("Unexpected database error: " + err.Error())
			return errs.NewUnexpectedError("Unexpected database error")
		}

	}

	return nil
}
