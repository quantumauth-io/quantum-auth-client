package http

import (
	"github.com/quantumauth-io/quantum-auth-client/internal/httpui"
)

func (s *Server) AttachUI() error {
	ui, err := httpui.Handler()
	if err != nil {
		return err
	}

	// IMPORTANT: attach last so it doesn't steal API routes.
	s.mux.Handle("/", ui)
	return nil
}
