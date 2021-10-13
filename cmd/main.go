package main

import (
	"log"

	"github.com/danisbagus/edagang-pkg/logger"
	"github.com/danisbagus/edagang-user/internal/core/service"
	"github.com/danisbagus/edagang-user/internal/handler"
	"github.com/danisbagus/edagang-user/internal/repo"

	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)

func main() {
	// sql driver
	client := GetClient()

	// multiplexer
	router := mux.NewRouter()

	// wiring
	authRepo := repo.NewAuthRepo(client)
	authService := service.NewAuthServie(authRepo)
	authHandler := handler.AuthHandler{Service: authService}

	// routing
	router.HandleFunc("/auth/login", authHandler.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", authHandler.Verify).Methods(http.MethodGet)
	router.HandleFunc("/auth/refresh", authHandler.Refresh).Methods(http.MethodPost)

	// starting server
	logger.Info("Starting user service")
	log.Fatal(http.ListenAndServe("localhost:9010", router))
}

func GetClient() *sqlx.DB {
	client, err := sqlx.Open("mysql", "root:danisbagus@tcp(localhost:9001)/edagang")
	if err != nil {
		panic(err)
	}

	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)

	return client
}
