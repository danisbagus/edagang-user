package dto

import (
	"errors"

	"github.com/danisbagus/edagang-pkg/errs"
	"github.com/danisbagus/edagang-user/internal/core/domain"
	"github.com/dgrijalva/jwt-go"
	validation "github.com/go-ozzo/ozzo-validation"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RefreshTokenRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (r LoginRequest) Validate() *errs.AppError {

	if err := validation.Validate(r.Username, validation.Required); err != nil {
		return errs.NewBadRequestError("Username is required")

	}

	if err := validation.Validate(r.Password, validation.Required); err != nil {
		return errs.NewBadRequestError("Password is required")

	}

	return nil
}

func (r RefreshTokenRequest) IsAccessTokenValid() *jwt.ValidationError {

	// 1.invalid token
	// 2.valid token expired
	_, err := jwt.Parse(r.AccessToken, func(t *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		var vErr *jwt.ValidationError
		if errors.As(err, &vErr) {
			return vErr
		}
	}
	return nil
}
