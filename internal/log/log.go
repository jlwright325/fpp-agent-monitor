package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu sync.Mutex
}

type entry struct {
	TS     string                 `json:"ts"`
	Level  string                 `json:"level"`
	Msg    string                 `json:"msg"`
	Fields map[string]interface{} `json:"fields,omitempty"`
}

func (l *Logger) Info(msg string, fields map[string]interface{}) {
	l.write(os.Stdout, "info", msg, fields)
}

func (l *Logger) Warn(msg string, fields map[string]interface{}) {
	l.write(os.Stdout, "warn", msg, fields)
}

func (l *Logger) Error(msg string, fields map[string]interface{}) {
	l.write(os.Stderr, "error", msg, fields)
}

func (l *Logger) write(w io.Writer, level, msg string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := entry{
		TS:     time.Now().UTC().Format(time.RFC3339Nano),
		Level:  level,
		Msg:    msg,
		Fields: fields,
	}
	b, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(w, "{\"ts\":%q,\"level\":%q,\"msg\":%q,\"marshal_error\":%q}\n", e.TS, level, msg, err.Error())
		return
	}
	w.Write(append(b, '\n'))
}
