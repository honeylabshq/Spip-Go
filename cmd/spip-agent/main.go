package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"spip/internal/config"
	"spip/internal/exporters/loom"
	"spip/internal/logging"
	"spip/internal/network"
	"spip/internal/tls"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.toml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	var logOutput *os.File
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		logOutput = f
	} else {
		logOutput = os.Stdout
	}

	var logger logging.Logger
	var loomShipper *loom.Shipper
	if cfg.Loom.Enabled {
		loomShipper = loom.NewShipper(&cfg.Loom, func(msg string) {
			fmt.Fprintf(os.Stderr, "loom: %s\n", msg)
		})
		loomCh, _ := loomShipper.Run()
		logger = logging.NewLoggerWithECSChannel(logOutput, loomCh)
	}
	if logger == nil {
		logger = logging.NewLogger(logOutput)
	}

	fmt.Fprintln(os.Stderr, "Starting Spip agent...")
	if cfg.Loom.Enabled {
		fmt.Fprintln(os.Stderr, "Loom enabled")
	}

	// Initialize TLS if configured
	var tlsHandler *tls.TLSHandler
	if cfg.IsTLSEnabled() {
		tlsHandler, err = tls.NewTLSHandler(&tls.Config{
			CertPath: cfg.CertPath,
			KeyPath:  cfg.KeyPath,
		})
		if err != nil {
			logger.Error("main", fmt.Sprintf("Failed to initialize TLS: %v", err))
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "TLS enabled")
	} else {
		fmt.Fprintln(os.Stderr, "Running in plain TCP mode")
	}

	// Determine runtime tuning with sensible defaults
	ratePerSec := float64(cfg.RateLimitPerSecond)
	if ratePerSec == 0 {
		ratePerSec = 20
	}
	burst := cfg.RateLimitBurst
	if burst == 0 {
		burst = 50000
	}
	readTimeout := time.Duration(cfg.ReadTimeoutSeconds) * time.Second
	if readTimeout == 0 {
		readTimeout = 30 * time.Second
	}
	writeTimeout := time.Duration(cfg.WriteTimeoutSeconds) * time.Second
	if writeTimeout == 0 {
		writeTimeout = 10 * time.Second
	}

	// Create network handler (community_id_seed from config, 0 = default)
	handler := network.NewHandler(logger, tlsHandler, ratePerSec, burst, readTimeout, writeTimeout, cfg.Name, cfg.CommunityIDSeed)

	// Create TCP listener
	addr := fmt.Sprintf("%s:%d", cfg.IP, cfg.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Error("main", fmt.Sprintf("Failed to create listener: %v", err))
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Fprintf(os.Stderr, "Listening on %s\n", addr)

	// Accept connections and handle graceful shutdown on signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				// If the listener is closed as part of shutdown, exit quietly.
				var netErr net.Error
				if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
					return
				}
				if errors.As(err, &netErr) && !netErr.Timeout() {
					logger.Error("main", fmt.Sprintf("Listener accept failed: %v", err))
				}
				return
			}

			tcpConn, ok := conn.(*net.TCPConn)
			if !ok {
				logger.Error("main", fmt.Sprintf("Unexpected non-TCP connection type: %T", conn))
				conn.Close()
				continue
			}

			go handler.HandleConnection(tcpConn)
		}
	}()

	// Wait for shutdown signal
	<-stop
	fmt.Fprintln(os.Stderr, "Shutdown signal received, closing listener")
	listener.Close()

	if err := handler.Shutdown(15 * time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "Graceful shutdown completed with error: %v\n", err)
	} else {
		fmt.Fprintln(os.Stderr, "Graceful shutdown completed")
	}
	if loomShipper != nil {
		loomShipper.Shutdown()
	}
}
