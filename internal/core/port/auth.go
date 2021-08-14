package port

import (
	"github.com/danisbagus/semimarket-auth/internal/core/domain"
	"github.com/danisbagus/semimarket-auth/internal/dto"
	"github.com/danisbagus/semimarket-auth/pkg/errs"
)

type IAuthRepo interface {
	FindOne(username string, password string) (*domain.Login, *errs.AppError)
}

type IAuthService interface {
	Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
}
