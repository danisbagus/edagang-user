package port

import (
	"github.com/danisbagus/edagang-pkg/errs"
	"github.com/danisbagus/edagang-user/internal/core/domain"
	"github.com/danisbagus/edagang-user/internal/dto"
)

type IAuthRepo interface {
	FindOne(username string, password string) (*domain.Login, *errs.AppError)
	VerifyAuthorization(role string, routeName string) bool
	GenerateAndSaveRefreshTokenStore(authToken domain.AuthToken) (string, *errs.AppError)
	RefreshTokenExists(refreshToken string) *errs.AppError
}

type IAuthService interface {
	Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError)
	Verify(urlParams map[string]string) *errs.AppError
	Refresh(req dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError)
}
