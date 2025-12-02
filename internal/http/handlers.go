package http

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Madeindreams/quantum-auth-client/internal/qa"
)

type Handler struct {
	client *qa.Client
}

func NewHandler(client *qa.Client) *Handler {
	return &Handler{client: client}
}

// -------- DTOs for local client API --------

type registerUserReq struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
	Username string `json:"username" binding:"required"`
}

type registerUserRes struct {
	UserID string `json:"user_id"`
}

type registerDeviceReq struct {
	UserID string `json:"user_id"     binding:"required"`
	Label  string `json:"label"       binding:"required"`
}

type registerDeviceRes struct {
	DeviceID string `json:"device_id"`
}

type challengeReq struct {
	DeviceID string `json:"device_id" binding:"required"`
}

type challengeRes struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       int64  `json:"nonce"`
	ExpiresAt   string `json:"expires_at"`
}

type verifyReq struct {
	ChallengeID string `json:"challenge_id" binding:"required"`
	DeviceID    string `json:"device_id"    binding:"required"`
	Nonce       int64  `json:"nonce"        binding:"required"`
	Password    string `json:"password"     binding:"required"`
}

type verifyRes struct {
	Authenticated bool   `json:"authenticated"`
	UserID        string `json:"user_id"`
}

type securePingReq struct {
	UserID   string `form:"user_id"   json:"user_id"   binding:"required"`
	DeviceID string `form:"device_id" json:"device_id" binding:"required"`
}

func (h *Handler) Health(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}

// POST /api/users/register
func (h *Handler) RegisterUser(c *gin.Context) {
	var req registerUserReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, err := h.client.RegisterUser(c.Request.Context(), req.Email, req.Password, req.Username)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, registerUserRes{UserID: userID})
}

// POST /api/devices/register
func (h *Handler) RegisterDevice(c *gin.Context) {
	var req registerDeviceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deviceID, err := h.client.RegisterDevice(c.Request.Context(), req.UserID, req.Label)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, registerDeviceRes{DeviceID: deviceID})
}

// POST /api/auth/challenge
func (h *Handler) AuthChallenge(c *gin.Context) {
	var req challengeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	chID, nonce, err := h.client.RequestChallenge(c.Request.Context(), req.DeviceID)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	// the upstream response also has ExpiresAt; we don't expose it yet
	c.JSON(http.StatusCreated, challengeRes{
		ChallengeID: chID,
		Nonce:       nonce,
		ExpiresAt:   "", // TODO: plumb through if needed
	})
}

// POST /api/auth/verify
func (h *Handler) AuthVerify(c *gin.Context) {
	var req verifyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ok, userID, err := h.client.CompleteChallenge(
		c.Request.Context(),
		req.ChallengeID,
		req.DeviceID,
		req.Nonce,
		req.Password,
	)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, verifyRes{
		Authenticated: ok,
		UserID:        userID,
	})
}

// GET /api/secure-ping?user_id=...&device_id=...
func (h *Handler) SecurePing(c *gin.Context) {
	var req securePingReq
	if err := c.ShouldBindQuery(&req); err != nil {
		// also allow JSON body
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	status, body, err := h.client.SecurePing(c.Request.Context(), req.UserID, req.DeviceID)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"upstream_status": status,
		"upstream_body":   body,
	})
}
