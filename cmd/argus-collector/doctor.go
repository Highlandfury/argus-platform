package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/collector/spool"
	"github.com/argus-platform/argus/internal/platform/config"
)

// cmdDoctor diagnoses configuration, identity, CA, spool, and connectivity.
func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.LoadCollector()
	if err != nil {
		fmt.Println("config      : FAIL", err)
		return 1
	}
	fmt.Println("config      : OK")

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		fmt.Println("data dir    : FAIL", err)
		return 1
	}
	probe := filepath.Join(cfg.DataDir, ".doctor-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		fmt.Println("data dir    : FAIL not writable:", err)
		return 1
	}
	_ = os.Remove(probe)
	fmt.Println("data dir    : OK", cfg.DataDir)

	if raw, err := os.ReadFile(cfg.CAFile); err != nil {
		fmt.Println("pinned CA   : FAIL", err)
	} else if len(raw) == 0 {
		fmt.Println("pinned CA   : FAIL empty file")
	} else {
		fmt.Println("pinned CA   : OK", cfg.CAFile)
	}

	idStore := identity.NewStore(cfg.DataDir)
	if id, enrolled, err := idStore.Load(); err != nil {
		fmt.Println("identity    : FAIL", err)
	} else if enrolled {
		days := int(time.Until(id.CertNotAfter).Hours() / 24)
		fmt.Printf("identity    : OK collector=%s cert_expires_in=%dd policy_v%d\n",
			id.CollectorID, days, id.PolicyVersion)
	} else {
		fmt.Println("identity    : WARN not enrolled yet")
		if loadEnrollToken(cfg) == "" {
			fmt.Println("token       : WARN none available (set the token file or ARGUS_ENROLL_TOKEN)")
		} else {
			fmt.Println("token       : OK available")
		}
	}

	sp, err := spool.Open(spool.Options{
		Dir:           filepath.Join(cfg.DataDir, "spool"),
		MaxBytes:      cfg.SpoolMaxBytes,
		FsyncInterval: time.Duration(cfg.FsyncIntervalMS) * time.Millisecond,
	})
	if err != nil {
		fmt.Println("spool       : FAIL", err)
	} else {
		st := sp.Stats()
		fmt.Printf("spool       : OK records=%d bytes=%d acked=%d highest=%d dropped=%d corrupt=%d degraded=%v\n",
			st.Records, st.Bytes, st.AckedSeq, st.HighestSeq, st.DroppedRecordsTotal, st.CorruptRecordsTotal, st.Degraded)
		if st.DroppedRecordsTotal > 0 {
			fmt.Println("spool       : WARN data was dropped under capacity pressure; inspect logs")
		}
		if st.CorruptRecordsTotal > 0 {
			fmt.Println("spool       : WARN corruption was recovered/quarantined; inspect *.corrupt files")
		}
		_ = sp.Close()
	}

	if conn, err := dialTCP(cfg.StreamAddr); err != nil {
		fmt.Println("stream addr : FAIL", err)
	} else {
		_ = conn.Close()
		fmt.Println("stream addr : OK", cfg.StreamAddr)
	}
	return 0
}
