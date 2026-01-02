package assets

import "context"

type Reader interface {
	ReadFile(ctx context.Context, path string) ([]byte, error)
	Exists(ctx context.Context, path string) (bool, error)
}

type Writer interface {
	WriteFile(ctx context.Context, path string, data []byte, perm uint32) error
}

type ReadWriter interface {
	Reader
	Writer
}
