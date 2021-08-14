package handler

import (
	"encoding/json"
	"net/http"

	"github.com/danisbagus/semimarket-auth/internal/core/port"
	"github.com/danisbagus/semimarket-auth/internal/dto"
	"github.com/danisbagus/semimarket-auth/pkg/logger"
)

type AuthHandler struct {
	Service port.IAuthService
}

func (rc AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		logger.Error("Error while decoding login request: " + err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	token, appErr := rc.Service.Login(loginRequest)
	if appErr != nil {
		writeResponse(w, appErr.Code, appErr.AsMessage())
		return
	}
	writeResponse(w, http.StatusOK, *token)

}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
