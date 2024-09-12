package middleware

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type responseWriter struct {
	http.ResponseWriter
	status int
	length int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.length += n
	return n, err
}

func AuditLogMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w}

		ctx := context.WithValue(r.Context(), "request_id", uuid.New().String())
		r = r.WithContext(ctx)

		next.ServeHTTP(rw, r)

		log.Printf("Audit Log: method=%s path=%s status=%d duration=%s ip=%s user_agent=%s request_id=%s",
			r.Method,
			r.URL.Path,
			rw.status,
			time.Since(start),
			r.RemoteAddr,
			r.UserAgent(),
			ctx.Value("request_id"),
		)
	}
}
