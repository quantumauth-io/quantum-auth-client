package http

import (
	_ "embed"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

//go:embed ui_index.html
var uiIndexHTML []byte

func NewRouter(h *Handler) *gin.Engine {
	r := gin.Default()

	// TODO improve cors so that apps can talk with the client from the local browser
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	api := r.Group("/api")
	{
		api.GET("/health", h.Health)

		api.POST("/users/register", h.RegisterUser)
		api.POST("/devices/register", h.RegisterDevice)

		api.POST("/auth/challenge", h.AuthChallenge)
		api.POST("/auth/verify", h.AuthVerify)

		api.GET("/secure-ping", h.SecurePing)
	}

	r.GET("/", func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", uiIndexHTML)
	})

	return r
}
