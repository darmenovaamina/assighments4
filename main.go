package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/csrf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

var (
	validate = validator.New()
	jwtKey   = []byte("I_like_cats")
	logger   *zap.Logger

	// Prometheus metrics
	requestCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Number of HTTP requests",
		},
		[]string{"method", "path"},
	)
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
	errorCounter = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "http_errors_total",
			Help: "Total number of HTTP errors",
		},
	)
)

func init() {
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	prometheus.MustRegister(requestCounter)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(errorCounter)
}

type UserInput struct {
	Email string `json:"email" validate:"required,email"`
	Age   int    `json:"age" validate:"gte=18,lte=100"`
}

func ErrorHandler(w http.ResponseWriter, r *http.Request) {
	logger.Error("An error occurred")
	errorCounter.Inc()
	http.Error(w, "An error occurred", http.StatusInternalServerError)
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

var csrfMiddleware = csrf.Protect(
	[]byte("32-byte-long-auth-key"),
	csrf.Secure(true),
)

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		duration := time.Since(start).Seconds()
		path := r.URL.Path
		method := r.Method

		logger.Info("HTTP Request",
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", rec.statusCode),
			zap.Float64("duration", duration),
		)

		requestCounter.WithLabelValues(method, path).Inc()
		requestDuration.WithLabelValues(method, path).Observe(duration)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Welcome to the Secure Go Web App"))
}

func ValidateHandler(w http.ResponseWriter, r *http.Request) {
	var input UserInput
	_ = json.NewDecoder(r.Body).Decode(&input)

	if err := validate.Struct(input); err != nil {
		logger.Warn("Validation failed", zap.Error(err))
		errorCounter.Inc()
		http.Error(w, "Invalid input: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Write([]byte("Input is valid"))
}

func main() {
	defer logger.Sync()

	r := mux.NewRouter()

	r.Use(SecurityHeaders)
	r.Use(RequestLogger)

	r.HandleFunc("/", HomeHandler)
	r.HandleFunc("/validate", ValidateHandler).Methods("POST")
	r.Handle("/admin", RoleCheck("admin")(Authenticate(http.HandlerFunc(AdminHandler))))
	r.Handle("/metrics", promhttp.Handler())

	go func() {
		logger.Info("Redirecting HTTP to HTTPS...")
		log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		})))
	}()

	logger.Info("Starting HTTPS server on :443...")
	log.Fatal(http.ListenAndServeTLS(":443", "server.crt", "server.key", csrfMiddleware(r)))
}
