/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"intel/isecl/sgx-caching-service/config"
	"intel/isecl/sgx-caching-service/constants"
	"intel/isecl/sgx-caching-service/repository/postgres"
	"intel/isecl/sgx-caching-service/repository"
	"intel/isecl/sgx-caching-service/resource"
	"intel/isecl/sgx-caching-service/tasks"
	"intel/isecl/sgx-caching-service/version" 
	"intel/isecl/lib/common/crypt"
	e "intel/isecl/lib/common/exec"
	cmw "intel/isecl/lib/common/middleware"
	"intel/isecl/lib/common/setup"
	"intel/isecl/lib/common/validation"
	cos "intel/isecl/lib/common/os"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	stdlog "log"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"

	// Import driver for GORM
	_ "github.com/jinzhu/gorm/dialects/postgres"

	//"intel/isecl/sgx-caching-service/types"
)

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string
	Config         *config.Configuration
	ConsoleWriter  io.Writer
	LogWriter      io.Writer
	HTTPLogWriter  io.Writer
}

func (a *App) printUsage() {
	w := a.consoleWriter()
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "    sgx-caching-service <command> [arguments]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Commands:")
	fmt.Fprintln(w, "    help|-h|-help    Show this help message")
	fmt.Fprintln(w, "    setup [task]     Run setup task")
	fmt.Fprintln(w, "    start            Start sgx-caching-service")
	fmt.Fprintln(w, "    status           Show the status of sgx-caching-service")
	fmt.Fprintln(w, "    stop             Stop sgx-caching-service")
	fmt.Fprintln(w, "    tlscertsha384    Show the SHA384 of the certificate used for TLS")
	fmt.Fprintln(w, "    uninstall        Uninstall sgx-caching-service")
	fmt.Fprintln(w, "    version          Show the version of sgx-caching-service")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Avaliable Tasks for setup:")
	fmt.Fprintln(w, "    sgx-caching-service setup database [-force] [--arguments=<argument_value>]")
	fmt.Fprintln(w, "        - Avaliable arguments are:")
	fmt.Fprintln(w, "            - db-host    alternatively, set environment variable SCS_DB_HOSTNAME")
	fmt.Fprintln(w, "            - db-port    alternatively, set environment variable SCS_DB_PORT")
	fmt.Fprintln(w, "            - db-user    alternatively, set environment variable SCS_DB_USERNAME")
	fmt.Fprintln(w, "            - db-pass    alternatively, set environment variable SCS_DB_PASSWORD")
	fmt.Fprintln(w, "            - db-name    alternatively, set environment variable SCS_DB_NAME")
	fmt.Fprintln(w, "            - db-sslmode <disable|allow|prefer|require|verify-ca|verify-full>")
	fmt.Fprintln(w, "                         alternatively, set environment variable SCS_DB_SSLMODE")
	fmt.Fprintln(w, "            - db-sslcert path to where the certificate file of database. Only applicable")
	fmt.Fprintln(w, "                         for db-sslmode=<verify-ca|verify-full. If left empty, the cert")
	fmt.Fprintln(w, "                         will be copied to /etc/sgx-caching-service/tdcertdb.pem")
	fmt.Fprintln(w, "                         alternatively, set environment variable SCS_DB_SSLCERT")
	fmt.Fprintln(w, "            - db-sslcertsrc <path to where the database ssl/tls certificate file>")
	fmt.Fprintln(w, "                         mandatory if db-sslcert does not already exist")
	fmt.Fprintln(w, "                         alternatively, set environment variable SCS_DB_SSLCERTSRC")
	fmt.Fprintln(w, "        - Run this command with environment variable SCS_DB_REPORT_MAX_ROWS and")
	fmt.Fprintln(w, "          SCS_DB_REPORT_NUM_ROTATIONS can update db rotation arguments")
	fmt.Fprintln(w, "    sgx-caching-service setup server [--port=<port>]")
	fmt.Fprintln(w, "        - Setup http server on <port>")
	fmt.Fprintln(w, "        - Environment variable SCS_PORT=<port> can be set alternatively")
	fmt.Fprintln(w, "    sgx-caching-service setup tls [--force] [--host_names=<host_names>]")
	fmt.Fprintln(w, "        - Use the key and certificate provided in /etc/threat-detection if files exist")
	fmt.Fprintln(w, "        - Otherwise create its own self-signed TLS keypair in /etc/sgx-caching-service for quality of life")
	fmt.Fprintln(w, "        - Option [--force] overwrites any existing files, and always generate self-signed keypair")
	fmt.Fprintln(w, "        - Argument <host_names> is a list of host names used by local machine, seperated by comma")
	fmt.Fprintln(w, "        - Environment variable SCS_TLS_HOST_NAMES=<host_names> can be set alternatively")
	fmt.Fprintln(w, "    sgx-caching-service setup admin [--user=<username>] [--pass=<password>]")
	fmt.Fprintln(w, "        - Environment variable SCS_ADMIN_USERNAME=<username> can be set alternatively")
	fmt.Fprintln(w, "        - Environment variable SCS_ADMIN_PASSWORD=<password> can be set alternatively")
	fmt.Fprintln(w, "    sgx-caching-service setup reghost [--user=<username>] [--pass=<password>]")
	fmt.Fprintln(w, "        - Environment variable SCS_REG_HOST_USERNAME=<username> can be set alternatively")
	fmt.Fprintln(w, "        - Environment variable SCS_REG_HOST_PASSWORD=<password> can be set alternatively")
	fmt.Fprintln(w, "")
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	return config.Global()
}

func (a *App) executablePath() string {
	if a.ExecutablePath != "" {
		return a.ExecutablePath
	}
	exec, err := os.Executable()
	if err != nil {
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exec
}

func (a *App) homeDir() string {
	if a.HomeDir != "" {
		return a.HomeDir
	}
	return constants.HomeDir
}

func (a *App) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDir
}

func (a *App) logDir() string {
	if a.LogDir != "" {
		return a.ConfigDir
	}
	return constants.LogDir
}

func (a *App) execLinkPath() string {
	if a.ExecLinkPath != "" {
		return a.ExecLinkPath
	}
	return constants.ExecLinkPath
}

func (a *App) runDirPath() string {
	if a.RunDirPath != "" {
		return a.RunDirPath
	}
	return constants.RunDirPath
}

func (a *App) configureLogs() {
	log.SetOutput(io.MultiWriter(os.Stderr, a.logWriter()))
	log.SetLevel(a.configuration().LogLevel)

	// override golang logger
	w := log.StandardLogger().WriterLevel(a.configuration().LogLevel)
	stdlog.SetOutput(w)
}

func (a *App) Run(args []string) error {
	a.configureLogs()

	if len(args) < 2 {
		a.printUsage()
		os.Exit(1)
	}

	cmd := args[1]
	switch cmd {
	default:
		a.printUsage()
		return errors.New("Unrecognized command: " + args[1])
	case "list":
		if len(args) < 3 {
			a.printUsage()
			os.Exit(1)
		}
		return a.PrintDirFileContents(args[2])
	case "run":
		if err := a.startServer(); err != nil {
			fmt.Fprintln(os.Stderr, "Error: daemon did not start - ", err.Error())
			// wait some time for logs to flush - otherwise, there will be no entry in syslog
			time.Sleep(10 * time.Millisecond)
			return err
		}
	case "-help":
		fallthrough
	case "--h":
		fallthrough
	case "--help":
		fallthrough
	case "help":
		a.printUsage()
	case "start":
		return a.start()
	case "stop":
		return a.stop()
	case "status":
		return a.status()
	case "uninstall":
		var keepConfig bool
		flag.CommandLine.BoolVar(&keepConfig, "keep-config", false, "keep config when uninstalling")
		flag.CommandLine.Parse(args[2:])
		a.uninstall(keepConfig)
		os.Exit(0)
	case "version":
		fmt.Fprintf(a.consoleWriter(), "SGX Caching Service %s-%s\n", version.Version, version.GitHash)
	case "setup":

		if len(args) <= 2 {
			a.printUsage()
			os.Exit(1)
		}

		if args[2] != "admin" &&
			args[2] != "download_ca_cert" &&
			args[2] != "download_cert" &&
			args[2] != "database" &&
			args[2] != "server" &&
			args[2] != "all" &&
			args[2] != "tls" {
			a.printUsage()
			return errors.New("No such setup task")
		}

		err := validateSetupArgs(args[2], args[3:])
		if err != nil {
			return err
		}

		a.Config = config.Global()
		var context setup.Context
		err = a.Config.SaveConfiguration(context)
                if err != nil {
                        fmt.Println("Error saving configuration: " + err.Error())
		        return errors.New("Configuration save ends with error")
                }

		task := strings.ToLower(args[2])
		flags := args[3:]
		setupRunner := &setup.Runner{
			Tasks: []setup.Task{
				setup.Download_Ca_Cert{
					Flags:         args,
					CmsBaseURL:    a.Config.CMSBaseUrl,
					CaCertDirPath: constants.TrustedCAsStoreDir,
					ConsoleWriter: os.Stdout,
				},
				setup.Download_Cert{
					Flags:              args,
					CmsBaseURL:    	    a.Config.CMSBaseUrl,
					KeyFile:            path.Join(a.configDir(), constants.TLSKeyFile),
					CertFile:           path.Join(a.configDir(), constants.TLSCertFile),
					KeyAlgorithm:       constants.DefaultKeyAlgorithm,
					KeyAlgorithmLength: constants.DefaultKeyAlgorithmLength,
					Subject: pkix.Name{
                                                Country:      []string{a.Config.Subject.Country},
                                                Organization: []string{a.Config.Subject.Organization},
                                                Locality:     []string{a.Config.Subject.Locality},
                                                Province:     []string{a.Config.Subject.Province},
                                                CommonName:   a.Config.Subject.TLSCertCommonName,
                                        },
					SanList:            constants.DefaultScsTlsSan,
					CertType:           "TLS",
					CaCertsDir:         constants.TrustedCAsStoreDir,
					BearerToken:        "",
					ConsoleWriter:      os.Stdout,
				},
				tasks.Database{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
				tasks.Admin{
					Flags: flags,
					DatabaseFactory: func() (repository.SCSDatabase, error) {
						pg := &a.configuration().Postgres
						p, err := postgres.Open(pg.Hostname, pg.Port, pg.DBName, pg.Username, pg.Password, pg.SSLMode, pg.SSLCert)
						if err != nil {
							log.WithError(err).Error("failed to open postgres connection for setup task")
							return nil, err
						}
						p.Migrate()
						return p, nil
					},
					ConsoleWriter: os.Stdout,
				},
				tasks.Server{
					Flags:         flags,
					Config:        a.configuration(),
					ConsoleWriter: os.Stdout,
				},
 				tasks.Root_Ca{
                                        Flags:            flags,
                                        ConsoleWriter:    os.Stdout,
                                        Config:           a.configuration(),
                                },

			},
			AskInput: false,
		}
		//var err error
		if task == "all" {
			err = setupRunner.RunTasks()
		} else {
			err = setupRunner.RunTasks(task)
		}
		if err != nil {
			log.WithError(err).Error("Error running setup")
			fmt.Println("Error running setup: ", err)
			return err
	        }	
	}
	return nil
}

func (a *App) retrieveJWTSigningCerts() error {
        c := a.configuration()
        log.WithField("AuthServiceUrl", c.AuthServiceUrl).Debug("URL dump")
        url := c.AuthServiceUrl + "noauth/jwt-certificates"
        req, _ := http.NewRequest("GET", url, nil)
        req.Header.Add("accept", "application/x-pem-file")
        rootCaCertPems, err := cos.GetDirFileContents(constants.RootCADirPath, "*.pem" )
        if err != nil {
                return err
        }

        // Get the SystemCertPool, continue with an empty pool on error
        rootCAs, _ := x509.SystemCertPool()
        if rootCAs == nil {
                rootCAs = x509.NewCertPool()
        }
        for _, rootCACert := range rootCaCertPems{
                if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
                        return err
                }
        }

        httpClient := &http.Client{
                                Transport: &http.Transport{
                                        TLSClientConfig: &tls.Config{
                                                InsecureSkipVerify: false,
                                                RootCAs: rootCAs,
                                                },
                                        },
                                }

        res, err := httpClient.Do(req)
        if err != nil {
        	log.WithError(err).Debug("Could not retrieve jwt certificate")
                return fmt.Errorf("Could not retrieve jwt certificate")
        }
        defer res.Body.Close()
        body, _ := ioutil.ReadAll(res.Body)
        err = crypt.SavePemCertWithShortSha1FileName(body, constants.TrustedJWTSigningCertsDir)
        if err != nil {
                fmt.Println("Could not store Certificate")
                return fmt.Errorf("Certificate setup: %v", err)
        }

        log.WithField("Retrieve JWT cert", "compledted").Debug("successfully")
        return nil
}

func (a *App) startServer() error {
	c := a.configuration()

	// verify the database connection. If this does not succeed then we want to exit right here
	// the Open method has a retry operation that takes a long time
	if err := postgres.VerifyConnection(c.Postgres.Hostname, c.Postgres.Port, c.Postgres.DBName,
		c.Postgres.Username, c.Postgres.Password, c.Postgres.SSLMode, c.Postgres.SSLCert); err != nil {
		return err
	}

	// Open database
	scsDB, err := postgres.Open(c.Postgres.Hostname, c.Postgres.Port, c.Postgres.DBName,
		c.Postgres.Username, c.Postgres.Password, c.Postgres.SSLMode, c.Postgres.SSLCert)
	if err != nil {
		log.WithError(err).Error("failed to open Postgres database")
		return err
	}
	defer scsDB.Close()
	scsDB.Migrate()

	// Create public routes that does not need any authentication
	r := mux.NewRouter()

	// Create Router, set routes
	sr := r.PathPrefix("/scs/sgx/certification/v1/").Subrouter()
	func(setters ...func(*mux.Router, repository.SCSDatabase)) {
		for _, setter := range setters {
			setter(sr, scsDB)
		}
	}(resource.QuoteProviderOps)


	sr = r.PathPrefix("/scs/sgx/platforminfo/").Subrouter()
	sr.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.TrustedCAsStoreDir, a.retrieveJWTSigningCerts))
	func(setters ...func(*mux.Router, repository.SCSDatabase)) {
		for _, setter := range setters {
			setter(sr, scsDB)
		}
	}(resource.PlatformInfoOps)


	sr = r.PathPrefix("/scs/test/").Subrouter()
	//sr.Use(cmw.NewTokenAuth(constants.TrustedJWTSigningCertsDir, constants.TrustedCAsStoreDir, a.retrieveJWTSigningCerts))
	func(setters ...func(*mux.Router)) {
		for _, setter := range setters {
			setter(sr)
		}
	}(resource.SetTestJwt)


	tlsconfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
	// Setup signal handlers to gracefully handle termination
	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	httpLog := stdlog.New(a.httpLogWriter(), "", 0)
	h := &http.Server{
		Addr:      fmt.Sprintf(":%d", c.Port),
		Handler:   handlers.RecoveryHandler(handlers.RecoveryLogger(httpLog), handlers.PrintRecoveryStack(true))(handlers.CombinedLoggingHandler(a.httpLogWriter(), r)),
		ErrorLog:  httpLog,
		TLSConfig: tlsconfig,
	}

	// dispatch web server go routine
	go func() {
		tlsCert := path.Join(a.configDir(), constants.TLSCertFile)
		tlsKey := path.Join(a.configDir(), constants.TLSKeyFile)
		if err := h.ListenAndServeTLS(tlsCert, tlsKey); err != nil {
			log.WithError(err).Info("Failed to start HTTPS server")
			stop <- syscall.SIGTERM
		}
	}()

	fmt.Fprintln(a.consoleWriter(), "SGX Caching Service is running")
	// TODO dispatch Service status checker goroutine
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		log.WithError(err).Info("Failed to gracefully shutdown webserver")
		return err
	}
	return nil
}

func (a *App) start() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start sgx-caching-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "start", "sgx-caching-service"}, os.Environ())
}

func (a *App) stop() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop sgx-caching-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "stop", "sgx-caching-service"}, os.Environ())
}

func (a *App) status() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status sgx-caching-service"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	return syscall.Exec(systemctl, []string{"systemctl", "status", "sgx-caching-service"}, os.Environ())
}

func (a *App) uninstall(keepConfig bool) {
	fmt.Println("Uninstalling SGX Caching Service")
	removeService()

	fmt.Println("removing : ", a.executablePath())
	err := os.Remove(a.executablePath())
	if err != nil {
		log.WithError(err).Error("error removing executable")
	}

	fmt.Println("removing : ", a.runDirPath())
	err = os.Remove(a.runDirPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.runDirPath())
	}
	fmt.Println("removing : ", a.execLinkPath())
	err = os.Remove(a.execLinkPath())
	if err != nil {
		log.WithError(err).Error("error removing ", a.execLinkPath())
	}

	if !keepConfig {
		fmt.Println("removing : ", a.configDir())
		err = os.RemoveAll(a.configDir())
		if err != nil {
			log.WithError(err).Error("error removing config dir")
		}
	}
	fmt.Println("removing : ", a.logDir())
	err = os.RemoveAll(a.logDir())
	if err != nil {
		log.WithError(err).Error("error removing log dir")
	}
	fmt.Println("removing : ", a.homeDir())
	err = os.RemoveAll(a.homeDir())
	if err != nil {
		log.WithError(err).Error("error removing home dir")
	}
	fmt.Fprintln(a.consoleWriter(), "SGX Caching Service uninstalled")
	a.stop()
}
func removeService() {
	_, _, err := e.RunCommandWithTimeout(constants.ServiceRemoveCmd, 5)
	if err != nil {
		fmt.Println("Could not remove SGX Caching Service")
		fmt.Println("Error : ", err)
	}
}

func validateCmdAndEnv(env_names_cmd_opts map[string]string, flags *flag.FlagSet) error {

	env_names := make([]string, 0)
	for k, _ := range env_names_cmd_opts {
		env_names = append(env_names, k)
	}

	missing, valid_err := validation.ValidateEnvList(env_names)
	if valid_err != nil && missing != nil {
		for _, m := range missing {
			if cmd_f := flags.Lookup(env_names_cmd_opts[m]); cmd_f == nil {
				return errors.New("Insufficient arguments")
			}
		}
	}
	return nil
}

func validateSetupArgs(cmd string, args []string) error {

	var fs *flag.FlagSet

	switch cmd {
	default:
		return errors.New("Unknown command")

	case "download_ca_cert":
		return nil

	case "download_cert":
	     return nil

	case "database":
		env_names_cmd_opts := map[string]string{
			"SCS_DB_HOSTNAME":   "db-host",
			"SCS_DB_PORT":       "db-port",
			"SCS_DB_USERNAME":   "db-user",
			"SCS_DB_PASSWORD":   "db-pass",
			"SCS_DB_NAME":       "db-name",
			"SCS_DB_SSLMODE":    "db-sslmode",
			"SCS_DB_SSLCERT":    "db-sslcert",
			"SCS_DB_SSLCERTSRC": "db-sslcertsrc",
		}

		fs = flag.NewFlagSet("database", flag.ContinueOnError)
		fs.String("db-host", "", "Database Hostname")
		fs.Int("db-port", 0, "Database Port")
		fs.String("db-user", "", "Database Username")
		fs.String("db-pass", "", "Database Password")
		fs.String("db-name", "", "Database Name")
		fs.String("db-sslmode", "", "Database SSL Mode")
		fs.String("db-sslcert", "", "Database SSL Cert Destination")
		fs.String("db-sslcertsrc", "", "Database SSL Cert Source File")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "admin":

		env_names_cmd_opts := map[string]string{
			"SCS_ADMIN_USERNAME": "user",
			"SCS_ADMIN_PASSWORD": "pass",
		}

		fs = flag.NewFlagSet("admin", flag.ContinueOnError)
		fs.String("user", "", "Username for admin authentication")
		fs.String("pass", "", "Password for admin authentication")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "reghost":

		env_names_cmd_opts := map[string]string{
			"SCS_REG_HOST_USERNAME": "user",
			"SCS_REG_HOST_PASSWORD": "pass",
		}

		fs = flag.NewFlagSet("reghost", flag.ContinueOnError)
		fs.String("user", "", "Username for host registration")
		fs.String("pass", "", "Password for host registration")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "server":
		// this has a default port value on 8443
		return nil

	case "tls":

		env_names_cmd_opts := map[string]string{
			"SCS_TLS_HOST_NAMES": "host_names",
		}

		fs = flag.NewFlagSet("tls", flag.ContinueOnError)
		fs.String("host_names", "", "comma separated list of hostnames to add to TLS self signed cert")

		err := fs.Parse(args)
		if err != nil {
			return fmt.Errorf("Fail to parse arguments: %s", err.Error())
		}
		return validateCmdAndEnv(env_names_cmd_opts, fs)

	case "all":
		if len(args) != 0 {
			return errors.New("Please setup the arguments with env")
		}
	}

	return nil
}
func (a* App) PrintDirFileContents(dir string) error {
        if dir == "" {
                return fmt.Errorf("PrintDirFileContents needs a directory path to look for files")
        }
        data, err := cos.GetDirFileContents(dir, "")
        if err != nil {
                return err
        }
        for i, fileData := range data {
                fmt.Println("File :", i)
                fmt.Printf("%s",fileData)
        }
        return nil
}

func (a *App) DatabaseFactory() (repository.SCSDatabase, error) {
	pg := &a.configuration().Postgres
	p, err := postgres.Open(pg.Hostname, pg.Port, pg.DBName, pg.Username, pg.Password, pg.SSLMode, pg.SSLCert)
	if err != nil {
		fmt.Println("failed to open postgres connection for setup task")
		return nil, err
	}
	return p, nil
}
