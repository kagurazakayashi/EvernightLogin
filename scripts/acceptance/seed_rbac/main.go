// Command seed_rbac is a test-fixture helper: grants the support permission
// preset to a temporary support role/user in a synthetic database. Test-only.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
)

func main() {
	dbPath := flag.String("database", "", "temporary SQLite database")
	roleID := flag.String("role-id", "", "support role id")
	supportUserID := flag.String("support-user-id", "", "support user id")
	rootUserID := flag.String("root-user-id", "", "assigning root user id")
	promotePasskeyUser := flag.String("promote-passkey-user-id", "", "fixture-only: mark existing login passkey as usable for second factor")
	flag.Parse()
	if *dbPath == "" || *roleID == "" || *supportUserID == "" || *rootUserID == "" {
		fmt.Fprintln(os.Stderr, "missing required flags")
		os.Exit(2)
	}
	ctx := context.Background()
	raw, err := sqlite.Open(ctx, sqlite.DefaultOptions(*dbPath))
	if err != nil {
		panic(err)
	}
	defer raw.Close()
	now := time.Now().UTC().UnixMilli()
	if *promotePasskeyUser != "" {
		if _, err := raw.DB().ExecContext(ctx, `UPDATE webauthn_credentials SET usage='both', updated_at_ms=?
WHERE user_id=? AND revoked_at_ms IS NULL AND usage='login'`, now, *promotePasskeyUser); err != nil {
			panic(err)
		}
	}
	keys := map[string]string{
		"support.cases.read":   "查看获准工单",
		"support.cases.create": "登记求助单",
		"support.cases.update": "更新获准工单",
	}
	for key, name := range keys {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		permID := "perm_" + hex.EncodeToString(b)
		if _, err := raw.DB().ExecContext(ctx, `INSERT INTO permissions(
id,scope_id,permission_key,name,description,limits_text,is_builtin,root_only,enabled,created_at_ms,updated_at_ms)
VALUES(?, 'system', ?, ?, '验收夹具权限', '仅获准支持范围', 0, 0, 1, ?, ?)
ON CONFLICT(scope_id,permission_key) DO NOTHING`, permID, key, name, now, now); err != nil {
			panic(err)
		}
		var realID string
		if err := raw.DB().QueryRowContext(ctx, `SELECT id FROM permissions WHERE scope_id='system' AND permission_key=?`, key).Scan(&realID); err != nil {
			panic(err)
		}
		if _, err := raw.DB().ExecContext(ctx, `INSERT OR IGNORE INTO role_permissions(role_id,permission_id,scope_id)
VALUES(?,?,'system')`, *roleID, realID); err != nil {
			panic(err)
		}
	}
	if _, err := raw.DB().ExecContext(ctx, `INSERT OR IGNORE INTO user_roles(
user_id,role_id,scope_id,data_scope_json,assigned_by,created_at_ms) VALUES(?,?,'system','{}',?,?)`,
		*supportUserID, *roleID, *rootUserID, now); err != nil {
		panic(err)
	}
	fmt.Println("seed_rbac ok")
}
