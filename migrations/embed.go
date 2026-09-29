// Package migrations embeds the SQL migration files so that the argus-server
// binary is self-contained: `argus-server migrate` needs no files on disk at
// runtime (the container image copies only the compiled binary).
//
// Governance: `Latest` must always equal the highest numbered migration file.
// The integration test TestLatestVersionMatchesFiles fails if they diverge.
package migrations

import "embed"

// FS contains all *.up.sql / *.down.sql files.
//
//go:embed *.sql
var FS embed.FS

// Latest is the highest migration version in this package.
const Latest uint = 5
