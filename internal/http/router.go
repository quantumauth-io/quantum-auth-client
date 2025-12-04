package http

import (
	_ "embed"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

//go:embed ui_index.html
var uiIndexHTML []byte

// SkipPathLogger returns a logger middleware that skips logging for given paths.
func SkipPathLogger(skipPaths ...string) gin.HandlerFunc {
	skip := make(map[string]struct{}, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = struct{}{}
	}

	baseLogger := gin.Logger()

	return func(c *gin.Context) {
		if _, ok := skip[c.Request.URL.Path]; ok {
			// just run the next handlers, no logging
			c.Next()
			return
		}
		// normal logging for all other paths
		baseLogger(c)
	}
}

func NewRouter(h *Handler) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	// use custom logger that skips /api/health
	r.Use(SkipPathLogger("/api/health"))
	r.Use(gin.Recovery())

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
