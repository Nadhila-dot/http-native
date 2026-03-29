package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
)

func main() {
	scenario := "static"
	if len(os.Args) > 1 {
		scenario = os.Args[1]
	}

	port := "3009"
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	switch scenario {
	case "static":
		app.Get("/", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"ok":     true,
				"engine": "fiber",
				"mode":   "static",
			})
		})
	case "dynamic":
		app.Get("/users/:id", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"id":     c.Params("id"),
				"engine": "fiber",
				"mode":   "dynamic",
			})
		})
	case "opt":
		app.Get("/stable", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"ok":           true,
				"engine":       "fiber",
				"mode":         "opt",
				"optimization": "runtime",
			})
		})
	default:
		log.Fatalf("unsupported scenario: %s", scenario)
	}

	app.Use(func(c *fiber.Ctx) error {
		c.Status(fiber.StatusNotFound)
		return c.JSON(fiber.Map{"error": "Route not found"})
	})

	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Printf("READY http://127.0.0.1:%s\n", port)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- app.Listener(listener)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-signals:
		shutdownDone := make(chan struct{})
		go func() {
			defer close(shutdownDone)
			_ = app.Shutdown()
		}()

		select {
		case <-shutdownDone:
		case <-time.After(5 * time.Second):
			log.Print("fiber shutdown timed out")
		}
	case err := <-serverErr:
		if err != nil {
			log.Fatal(err)
		}
	}
}
