package service

import (
	"github.com/danisbagus/semimarket-auth/internal/core/domain"
	"github.com/danisbagus/semimarket-auth/internal/core/port"
	"github.com/danisbagus/semimarket-auth/internal/dto"

	"github.com/danisbagus/semimarket-auth/pkg/errs"
)

type AuthService struct {
	repo port.IAuthRepo
}

func NewAuthServie(repo port.IAuthRepo) port.IAuthService {
	return &AuthService{
		repo: repo,
	}
}

func (r AuthService) Login(req dto.LoginRequest) (*dto.LoginResponse, *errs.AppError) {
	var appErr *errs.AppError
	var login *domain.Login

	err := req.Validate()

	if err != nil {
		return nil, err
	}

	if login, appErr = r.repo.FindOne(req.Username, req.Password); appErr != nil {
		return nil, appErr
	}

	claims := login.ClaimsForAccessToken()

	authToken := domain.NewAuthToken(claims)

	var accessToken string
	if accessToken, appErr = authToken.NewAccessToken(); appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{AccessToken: accessToken}, nil

}
