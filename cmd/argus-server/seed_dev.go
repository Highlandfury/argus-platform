package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/collectors"
	"github.com/argus-platform/argus/internal/modules/tenancy"
	"github.com/argus-platform/argus/internal/platform/config"
	"github.com/argus-platform/argus/internal/platform/database"
	"github.com/argus-platform/argus/internal/platform/security"
)

// cmdSeedDev converges the development organization/site/admin user.
// Idempotent: re-running refreshes the admin password and returns stable ids.
func cmdSeedDev(args []string) int {
	fs := flag.NewFlagSet("seed-dev", flag.ContinueOnError)
	force := fs.Bool("force", false, "allow running against ARGUS_ENV=prod")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	if cfg.Env == config.EnvProd && !*force {
		fmt.Fprintln(os.Stderr, "seed-dev refuses to run with ARGUS_ENV=prod (use -force to override explicitly)")
		return 1
	}
	if cfg.DBDSN == "" || cfg.AuthDBDSN == "" {
		fmt.Fprintln(os.Stderr, "seed-dev requires ARGUS_SERVER_DB_DSN and ARGUS_SERVER_AUTH_DB_DSN")
		return 1
	}

	password := os.Getenv("ARGUS_DEV_ADMIN_PASSWORD")
	if password == "" {
		password = "dev-admin-changeme"
		fmt.Fprintln(os.Stderr, "warning: ARGUS_DEV_ADMIN_PASSWORD not set; using the documented development default")
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash password:", err)
		return 1
	}

	ctx := context.Background()
	appPool, err := database.NewPool(ctx, cfg.DBDSN, "argus-seed", database.DefaultPoolConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, "database:", err)
		return 1
	}
	defer appPool.Close()
	authPool, err := database.NewPool(ctx, cfg.AuthDBDSN, "argus-seed-auth", database.DefaultPoolConfig())
	if err != nil {
		fmt.Fprintln(os.Stderr, "auth database:", err)
		return 1
	}
	defer authPool.Close()

	res, err := tenancy.SeedDev(ctx, appPool, authPool, tenancy.SeedParams{
		Slug:              "dev",
		OrgName:           "Dev Org",
		SiteName:          "HQ",
		AdminEmail:        "admin@dev.local",
		AdminPasswordHash: hash,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "seed:", err)
		return 1
	}

	doc := map[string]any{
		"seeded_at":     time.Now().UTC().Format(time.RFC3339),
		"org_id":        res.OrgID,
		"org_slug":      "dev",
		"site_id":       res.SiteID,
		"admin_email":   res.Email,
		"admin_user_id": res.UserID,
		"note":          "development-only seed state; enrollment tokens arrive in M3",
	}
	if err := os.MkdirAll(".dev", 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "warning: cannot create .dev directory:", err)
	} else {
		raw, _ := json.MarshalIndent(doc, "", "  ")
		path := filepath.Join(".dev", "seed.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "warning: cannot write seed state:", err)
		} else {
			fmt.Printf("seed-dev: wrote %s\n", path)
		}
	}

	fmt.Printf("seed-dev: org=%s site=%s admin=%s (created: org=%t site=%t user=%t)\n",
		res.OrgID, res.SiteID, res.Email, res.CreatedOrg, res.CreatedSite, res.CreatedUser)

	// M3: provision a development enrollment token for the seeded site. The raw
	// token is written to the requested path (shared CA volume in compose) and
	// never printed.
	if outPath := os.Getenv("ARGUS_DEV_ENROLLMENT_TOKEN_OUT"); outPath != "" {
		orgID, orgErr := uuid.Parse(res.OrgID)
		siteID, siteErr := uuid.Parse(res.SiteID)
		userID, userErr := uuid.Parse(res.UserID)
		if orgErr != nil || siteErr != nil || userErr != nil {
			fmt.Fprintln(os.Stderr, "warning: cannot provision enrollment token:", orgErr, siteErr, userErr)
			return 0
		}
		svc := collectors.New(appPool, authPool, nil, nil)
		raw, _, expiresAt, err := svc.CreateEnrollmentToken(ctx, orgID, siteID, 24*time.Hour, &userID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: enrollment token:", err)
			return 0
		}
		if err := os.WriteFile(outPath, []byte(raw+"\n"), 0o600); err != nil { //nolint:gosec // operator-configured dev path
			fmt.Fprintln(os.Stderr, "warning: write enrollment token:", err)
			return 0
		}
		fmt.Printf("seed-dev: wrote development enrollment token to %s (site %s, expires %s)\n",
			outPath, res.SiteID, expiresAt.UTC().Format(time.RFC3339))
	}
	return 0
}
