package domain

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

const ACCESS_TOKEN_DURATION = time.Hour
const HMAC_SAMPLE_SECRET = "semimarket-secret"

type AccessTokenClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.StandardClaims
}
