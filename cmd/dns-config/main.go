package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/GoreeCloud/DNS/internal/configbackup"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: dns-config backup|verify|restore [flags]")
		os.Exit(2)
	}
	command := os.Args[1]
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	archive := fs.String("archive", "", "encrypted backup file")
	identity := fs.String("identity", "", "owner-only age identity for verification/restoration")
	rules := fs.String("rules", "", "validated rules.txt input")
	local := fs.String("records", "", "validated local-records.txt input")
	recipient := fs.String("recipient", "", "public age X25519 recipient")
	out := fs.String("out", "", "new encrypted backup path")
	target := fs.String("target", "", "new empty staging directory for optional restore")
	apply := fs.Bool("apply", false, "explicitly write verified policy to a NEW directory; never overwrite")
	if e := fs.Parse(os.Args[2:]); e != nil {
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var err error
	switch command {
	case "backup":
		if *rules == "" || *local == "" || *recipient == "" || *out == "" {
			fs.Usage()
			os.Exit(2)
		}
		err = configbackup.Backup(ctx, *rules, *local, *recipient, *out)
	case "verify":
		if *archive == "" || *identity == "" {
			fs.Usage()
			os.Exit(2)
		}
		err = configbackup.Verify(ctx, *archive, *identity)
	case "restore":
		if *archive == "" || *identity == "" || *target == "" {
			fs.Usage()
			os.Exit(2)
		}
		err = configbackup.Restore(ctx, *archive, *identity, *target, *apply)
	default:
		fs.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "DNS config operation failed:", err)
		os.Exit(1)
	}
	fmt.Println("DNS policy configuration operation validated; live DNS was not modified.")
}
