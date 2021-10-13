package service

import (
	"fmt"

	"github.com/danisbagus/edagang-user/internal/core/domain"
	"github.com/danisbagus/edagang-user/internal/core/port"
	"github.com/danisbagus/edagang-user/internal/dto"
	"github.com/dgrijalva/jwt-go"

	"github.com/danisbagus/edagang-pkg/errs"
	"github.com/danisbagus/edagang-pkg/logger"
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

	var refreshToken string
	if refreshToken, appErr = r.repo.GenerateAndSaveRefreshTokenStore(authToken); appErr != nil {
		return nil, appErr
	}

	return &dto.LoginResponse{AccessToken: accessToken, RefreshToken: refreshToken}, nil

}

func (r AuthService) Verify(urlParams map[string]string) *errs.AppError {

	jwtToken, err := jwtTokenFromString(urlParams["token"])
	if err != nil {
		return errs.NewAuthorizationError(err.Error())
	}

	if !jwtToken.Valid {
		return errs.NewAuthorizationError("Invalid token")
	}

	claims := jwtToken.Claims.(*domain.AccessTokenClaims)

	isAuthorized := r.repo.VerifyAuthorization(claims.Role, urlParams["routeName"])
	if !isAuthorized {
		return errs.NewAuthorizationError(fmt.Sprintf("%s role is not authorized", claims.Role))
	}

	return nil
}

func (r AuthService) Refresh(req dto.RefreshTokenRequest) (*dto.LoginResponse, *errs.AppError) {
	if vErr := req.IsAccessTokenValid(); vErr != nil {
		if vErr.Errors == jwt.ValidationErrorExpired {
			// do refresh token
			var appErr *errs.AppError
			if appErr = r.repo.RefreshTokenExists(req.RefreshToken); appErr != nil {
				return nil, appErr
			}

			// generate access token from refresh token
			var accessToken string
			if accessToken, appErr = domain.NewAccessTokenFromRefreshToken(req.RefreshToken); appErr != nil {
				return nil, appErr
			}

			return &dto.LoginResponse{AccessToken: accessToken}, nil
		}
		return nil, errs.NewAuthenticationError("Invalid token")
	}

	return nil, errs.NewAuthenticationError("Cannot generate new access token until the current access token expires")
}

func jwtTokenFromString(tokenString string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(domain.HMAC_SAMPLE_SECRET), nil
	})
	if err != nil {
		logger.Error("Error while parsing token: " + err.Error())
		return nil, err
	}
	return token, nil
}
