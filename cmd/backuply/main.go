package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/IlyaBOT/Backuply/internal/config"
	"github.com/IlyaBOT/Backuply/internal/daemon"
	"github.com/IlyaBOT/Backuply/internal/identity"
	"github.com/IlyaBOT/Backuply/internal/store"
)

var version = "dev"

func main() {
	if err := execute(os.Args[1:]); err != nil { fmt.Fprintln(os.Stderr,"backuply:",err); os.Exit(1) }
}

func execute(args []string) error {
	if len(args)==0 { usage(); return errors.New("a command is required") }
	if args[0]=="help" || args[0]=="-h" || args[0]=="--help" { usage(); return nil }
	if args[0]=="version" { fmt.Println("backuply",version,"(single-writer-v1)"); return nil }
	command:=args[0]
	switch command { case "run","init","id","check","status": default: return fmt.Errorf("unknown command %q",command) }
	flags:=flag.NewFlagSet(command,flag.ContinueOnError)
	configPath:=flags.String("config","/etc/backuply/backuply.conf","configuration file")
	var stateDir string
	if command=="init" || command=="id" { flags.StringVar(&stateDir,"state-dir","","identity directory (without loading a configuration)") }
	if err:=flags.Parse(args[1:]); err!=nil { if errors.Is(err,flag.ErrHelp){return nil}; return err }
	if flags.NArg()!=0 { return errors.New("unexpected positional arguments") }
	var cfg config.Config
	if stateDir!="" {
		if !filepath.IsAbs(stateDir) { return errors.New("state-dir must be absolute") }
		configExplicit:=false
		flags.Visit(func(f *flag.Flag){if f.Name=="config" {configExplicit=true}})
		if configExplicit { return errors.New("choose either -config or -state-dir") }
		cfg.StateDir=filepath.Clean(stateDir)
	} else {
		var err error
		cfg,err=config.Load(*configPath)
		if err!=nil{return err}
	}
	switch command {
	case "check": fmt.Println("configuration OK"); return nil
	case "init":
		lock,err:=daemon.LockState(cfg.StateDir); if err!=nil{return err}; defer lock.Close()
		id,err:=identity.LoadOrCreate(cfg.StateDir); if err!=nil{return err}
		for _,folder:=range cfg.Folders { if err:=store.InitFolder(folder.Path,folder.ID);err!=nil{return fmt.Errorf("initialize folder %s: %w",folder.ID,err)} }
		fmt.Println(id.ID); return nil
	case "id":
		id,err:=identity.Load(cfg.StateDir);if err!=nil{return err};fmt.Println(id.ID);return nil
	case "status":
		status,err:=daemon.QueryStatus(context.Background(),cfg.StateDir);if err!=nil{return err}
		if !status.Running{return errors.New("daemon is not running")}
		enc:=json.NewEncoder(os.Stdout);enc.SetIndent("","  ");return enc.Encode(status)
	case "run":
		logger:=slog.New(slog.NewJSONHandler(os.Stderr,nil))
		d,err:=daemon.New(cfg,logger);if err!=nil{return err};defer d.Close()
		ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
		return d.Run(ctx)
	}
	return nil
}

func usage(){fmt.Fprintln(os.Stdout,`Usage: backuply COMMAND [options]

  init    -config FILE       create identity and explicitly mark configured folders
  init    -state-dir PATH    create identity before pairing devices
  id      -config FILE       print the existing device fingerprint
  check   -config FILE       validate configuration without changing files
  run     -config FILE       run foreground (systemd/Docker manages backgrounding)
  status  -config FILE       query the local daemon via its private Unix socket
  version                   print build version

Default config: /etc/backuply/backuply.conf
Stage one: Linux, one writer per folder, static peers, TCP/TLS, fixed-size blocks.
Deletion propagation and concurrent editing are not supported yet.`)}
