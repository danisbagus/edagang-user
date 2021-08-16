package main

import (
	"log"

	"github.com/danisbagus/semimarket-auth/internal/core/service"
	"github.com/danisbagus/semimarket-auth/internal/handler"
	"github.com/danisbagus/semimarket-auth/internal/repo"
	"github.com/danisbagus/semimarket-lib/logger"

	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
)

func main() {
	// sql driver
	client, err := sqlx.Open("mysql", "root:danisbagus@tcp(localhost:9001)/semimarket")
	if err != nil {
		panic(err)
	}

	client.SetConnMaxLifetime(time.Minute * 3)
	client.SetMaxOpenConns(10)
	client.SetMaxIdleConns(10)

	// multiplexer
	router := mux.NewRouter()

	// wiring
	authRepo := repo.NewAuthRepo(client)
	authService := service.NewAuthServie(authRepo)
	authHandler := handler.AuthHandler{Service: authService}

	// routing
	router.HandleFunc("/auth/login", authHandler.Login).Methods(http.MethodPost)
	router.HandleFunc("/auth/verify", authHandler.Verify).Methods(http.MethodGet)

	// starting server
	logger.Info("Starting the auth service ...")
	log.Fatal(http.ListenAndServe("localhost:9010", router))
}
