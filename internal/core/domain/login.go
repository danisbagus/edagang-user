package domain

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type Login struct {
	UserID    string `db:"user_id"`
	Username  string `db:"username"`
	Password  string `db:"password"`
	Role      string `db:"role"`
	CreatedOn string `db:"created_on"`
}

func (r Login) ClaimsForAccessToken() AccessTokenClaims {
	return AccessTokenClaims{
		UserID: r.UserID,
		Role:   r.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(ACCESS_TOKEN_DURATION).Unix(),
		},
	}
}
