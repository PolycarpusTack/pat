package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"
)

func main() {
	var (
		migrationsPath = flag.String("path", "migrations", "path to migrations")
		dbURL          = flag.String("database", "", "database URL")
		command        = flag.String("command", "up", "migration command: up, down, version, force VERSION, goto VERSION")
		version        = flag.Int("version", 0, "migration version for force/goto commands")
	)
	flag.Parse()

	if *dbURL == "" {
		*dbURL = os.Getenv("DATABASE_URL")
		if *dbURL == "" {
			log.Fatal("database URL is required")
		}
	}

	// Open database connection
	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create driver
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatalf("failed to create driver: %v", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", *migrationsPath),
		"postgres",
		driver,
	)
	if err != nil {
		log.Fatalf("failed to create migrate instance: %v", err)
	}

	// Execute command
	switch *command {
	case "up":
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("failed to run migrations: %v", err)
		}
		log.Println("Migrations completed successfully")

	case "down":
		if err := m.Down(); err != nil && err != migrate.ErrNoChange {
			log.Fatalf("failed to rollback migrations: %v", err)
		}
		log.Println("Rollback completed successfully")

	case "version":
		version, dirty, err := m.Version()
		if err != nil {
			log.Fatalf("failed to get version: %v", err)
		}
		fmt.Printf("Version: %d, Dirty: %v\n", version, dirty)

	case "force":
		if *version == 0 {
			log.Fatal("version is required for force command")
		}
		if err := m.Force(*version); err != nil {
			log.Fatalf("failed to force version: %v", err)
		}
		log.Printf("Forced to version %d", *version)

	case "goto":
		if *version == 0 {
			log.Fatal("version is required for goto command")
		}
		if err := m.Migrate(uint(*version)); err != nil {
			log.Fatalf("failed to migrate to version: %v", err)
		}
		log.Printf("Migrated to version %d", *version)

	default:
		log.Fatalf("unknown command: %s", *command)
	}
}