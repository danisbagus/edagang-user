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

func (rc AuthHandler) Verify(w http.ResponseWriter, r *http.Request) {
	urlParams := make(map[string]string)

	for k := range r.URL.Query() {
		urlParams[k] = r.URL.Query().Get(k)
	}

	if urlParams["token"] == "" {
		writeResponse(w, http.StatusForbidden, notAuthorizedResponse("Missing token"))
		return
	}

	appErr := rc.Service.Verify(urlParams)
	if appErr != nil {
		writeResponse(w, appErr.Code, notAuthorizedResponse(appErr.Message))
		return
	}

	writeResponse(w, http.StatusOK, authorizedResponse())
}

func notAuthorizedResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"isAuthorized": false,
		"message":      msg,
	}
}

func authorizedResponse() map[string]bool {
	return map[string]bool{"isAuthorized": true}
}

func writeResponse(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		panic(err)
	}
}
