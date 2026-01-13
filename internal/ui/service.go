package ui

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/quantumauth-io/quantum-auth-client/internal/quantum-auth-client/httpui"
	"github.com/quantumauth-io/quantum-go-utils/log"
)

type Config struct {
	Addr string
}

type Service struct {
	cfg Config
	srv *http.Server
	ln  net.Listener
}

func NewUi(cfg Config) *Service {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:5173"
	}
	return &Service{cfg: cfg}
}

func (s *Service) Start() error {
	h, err := httpui.Handler()
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.ln = ln

	s.srv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {

		err := s.srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			log.Error("Failed to start server", "", err.Error())
		}
	}()

	return nil
}

func (s *Service) URL() string {
	if s.ln == nil {
		return ""
	}
	return fmt.Sprintf("http://%s", s.ln.Addr().String())
}

func (s *Service) Stop(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}
