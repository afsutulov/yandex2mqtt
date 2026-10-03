package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gofrs/flock"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"yandex2mqtt/bridge"
)

var version = "1.2.5"

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "yandex2mqtt:", e)
		os.Exit(1)
	}
}
func run() error {
	config := flag.String("config", "config.json", "configuration path")
	check := flag.Bool("check", false, "validate configuration and exit")
	hash := flag.Bool("hash-password", false, "read password from terminal/stdin and output bcrypt hash")
	migrate := flag.String("migrate", "", "migrate exported legacy JSON")
	output := flag.String("output", "config.json", "migration output (must not exist)")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println("yandex2mqtt-go", version)
		return nil
	}
	if *hash {
		var b []byte
		var e error
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprint(os.Stderr, "Password: ")
			b, e = term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
		} else {
			b, e = io.ReadAll(io.LimitReader(os.Stdin, 74))
			b = []byte(strings.TrimRight(string(b), "\r\n"))
		}
		if e != nil {
			return e
		}
		if len(b) == 0 || len(b) > 72 {
			return fmt.Errorf("password must contain 1..72 bytes")
		}
		h, e := bcrypt.GenerateFromPassword(b, 12)
		if e != nil {
			return e
		}
		fmt.Println(string(h))
		return nil
	}
	if *migrate != "" {
		return bridge.Migrate(*migrate, *output)
	}
	c, e := bridge.LoadConfig(*config)
	if e != nil {
		return e
	}
	if *check {
		fmt.Printf("Configuration OK: %d devices, %d users\n", len(c.Devices), len(c.Users))
		return nil
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if e := os.MkdirAll(filepath.Dir(c.DataFile), 0700); e != nil {
		return e
	}
	lock := flock.New(c.DataFile + ".lock")
	locked, e := lock.TryLock()
	if e != nil {
		return e
	}
	if !locked {
		return fmt.Errorf("another process is using this token store")
	}
	defer lock.Unlock()
	for _, u := range c.Users {
		if u.PasswordHash == "" {
			log.Warn("plaintext password in configuration; migrate to passwordHash", "user_id", u.ID)
		}
	}
	store, e := bridge.OpenStore(c.DataFile)
	if e != nil {
		return e
	}
	mqtt, e := bridge.NewMQTT(c.MQTT, log)
	if e != nil {
		return e
	}
	registry := bridge.NewRegistry(c, mqtt)
	server, e := bridge.NewServer(c, registry, store, log)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	notifier := bridge.NewNotifier(c.Notification, registry, store, log)
	registry.OnChange = notifier.Enqueue
	notifier.Start(ctx)
	mqtt.Start(ctx, registry)
	httpServer := &http.Server{Addr: c.HTTP.Listen, Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	if c.HTTPS.Certificate != "" {
		// Renewed certificates are picked up without a restart.
		certs, e := bridge.NewCertReloader(c.HTTPS.Certificate, c.HTTPS.PrivateKey, log)
		if e != nil {
			return e
		}
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: certs.GetCertificate}
	}
	errs := make(chan error, 1)
	go func() {
		log.Info("server started", "address", c.HTTP.Listen, "version", version, "devices", len(c.Devices), "tls", c.HTTPS.Certificate != "")
		if c.HTTPS.Certificate != "" {
			errs <- httpServer.ListenAndServeTLS("", "")
		} else {
			errs <- httpServer.ListenAndServe()
		}
	}()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-errs:
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdown)
	mqtt.Close()
	notifier.Wait()
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}
	return nil
}
