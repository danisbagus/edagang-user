package dto

import (
	"github.com/danisbagus/edagang-package/errs"
	validation "github.com/go-ozzo/ozzo-validation"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
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
