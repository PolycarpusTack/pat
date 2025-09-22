module github.com/pat-fortress

go 1.21

require (
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/websocket v1.5.3 // Updated from v1.5.0 - Security fixes

	// Testing
	github.com/stretchr/testify v1.9.0 // indirect
	go.uber.org/zap v1.27.0 // Updated from v1.26.0
	golang.org/x/crypto v0.25.0 // Updated from v0.18.0 - CRITICAL security updates
)

require go.uber.org/multierr v1.11.0 // indirect
