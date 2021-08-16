package port

import (
	"github.com/danisbagus/semimarket-auth/internal/core/domain"
	"github.com/danisbagus/semimarket-auth/internal/dto"
	"github.com/danisbagus/semimarket-lib/errs"
)

type IAuthRepo interface {
	FindOne(username string, password string) (*domain.Login, *errs.AppError)
	VerifyAuthorization(role string, routeName string) bool
}

type IAuthService interface {
	Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
}
