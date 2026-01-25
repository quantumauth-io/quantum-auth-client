package state

import (
	"fmt"
	"sync"
	"time"

	"fyne.io/fyne/v2/data/binding"
)

type UILogger struct {
	mu    sync.Mutex
	lines binding.StringList
	limit int
}

func NewUILogger(limit int) *UILogger {
	if limit <= 0 {
		limit = 500
	}
	return &UILogger{
		lines: binding.NewStringList(),
		limit: limit,
	}
}

func (l *UILogger) Lines() binding.StringList { return l.lines }

func (l *UILogger) Addf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().Format("15:04:05")
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %s", ts, msg)

	_ = l.lines.Append(line)

	// trim oldest (v2.7+ list is value-based; do slice Set)
	items, err := l.lines.Get()
	if err != nil {
		return
	}
	if len(items) > l.limit {
		items = items[len(items)-l.limit:]
		_ = l.lines.Set(items)
	}
}
