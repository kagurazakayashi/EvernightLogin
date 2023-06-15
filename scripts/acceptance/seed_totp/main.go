// Command seed_totp is a test-fixture helper that injects a real active TOTP
// binding for a synthetic temporary database. It is not part of the product and
// is only invoked by scripts/acceptance/strong_auth_fixture.py.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/totp"
)

func main() {
	dbPath := flag.String("database", "", "temporary SQLite database")
	masterPath := flag.String("master-key", "", "master key file")
	username := flag.String("username", "root", "target username")
	markReady := flag.Bool("mark-ready", false, "fixture-only: mark root initialization ready after seeding a real TOTP factor")
	outPath := flag.String("out", "", "output JSON with Base32 secret (fixture-only, temporary)")
	flag.Parse()
	if *dbPath == "" || *masterPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flags")
		os.Exit(2)
	}
	ctx := context.Background()
	raw, err := sqlite.Open(ctx, sqlite.DefaultOptions(*dbPath))
	if err != nil {
		fail(err)
	}
	defer raw.Close()
	provider, err := secrets.NewFileProvider(*masterPath)
	if err != nil {
		fail(err)
	}
	ring, err := secrets.LoadKeyring(ctx, provider)
	if err != nil {
		fail(err)
	}
	sealer, err := secrets.NewSealer(ring, nil)
	if err != nil {
		fail(err)
	}
	var userID string
	if err := raw.DB().QueryRowContext(ctx, `SELECT id FROM users WHERE username_normalized=?`, *username).Scan(&userID); err != nil {
		fail(err)
	}
	secret, err := totp.GenerateSecret(rand.Reader)
	if err != nil {
		fail(err)
	}
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		fail(err)
	}
	bindingID := "tfb_" + hex.EncodeToString(buffer)
	sealed, err := sealer.Seal(secrets.Binding{Purpose: "mfa.totp", ObjectID: bindingID, ScopeID: secrets.ScopeSystem}, secret)
	if err != nil {
		fail(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	expires := now.Add(24 * time.Hour)
	if _, err := raw.DB().ExecContext(ctx, `INSERT INTO totp_bindings(
id,user_id,status,sealed_secret,algorithm,digits,period_seconds,window_steps,
last_accepted_step,attempts,max_attempts,expires_at_ms,created_at_ms,updated_at_ms,activated_at_ms
) VALUES(?,?,'active',?,'SHA1',6,30,1,-1,0,5,?,?,?,?)`,
		bindingID, userID, sealed, expires.UnixMilli(), now.UnixMilli(), now.UnixMilli(), now.UnixMilli()); err != nil {
		fail(err)
	}
	doc := map[string]string{"username": *username, "secret": totp.EncodeSecret(secret), "binding_id": bindingID}
	encoded, _ := json.Marshal(doc)
	if *markReady {
		nowMS := now.UnixMilli()
		if _, err := raw.DB().ExecContext(ctx, `UPDATE root_initializations SET state='ready', verified_at_ms=COALESCE(verified_at_ms,?), ready_at_ms=? WHERE singleton=1`,
			nowMS, nowMS); err != nil {
			fail(err)
		}
	}
	if err := os.WriteFile(*outPath, encoded, 0o600); err != nil {
		fail(err)
	}
	fmt.Println("seed_totp ok")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "seed_totp:", err)
	os.Exit(1)
}
