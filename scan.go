package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/malice-plugins/pkgs/database"
	"github.com/malice-plugins/pkgs/database/elasticsearch"
	"github.com/malice-plugins/pkgs/utils"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const (
	name     = "pdf"
	category = "document"

	// pyScript is the Python 3.12 PDF analysis script shipped in the image.
	// The Go wrapper is a thin fire-and-forget shell around it: it runs the
	// script, parses the JSON result document, and stores it in Elasticsearch
	// via the shared pkgs library (exactly how the classic engine wrote
	// plugins.document.pdf).
	pyScript = "/app/pdfscan.py"
)

var (
	// Version stores the plugin's version
	Version string
	// BuildTime stores the plugin's build time
	BuildTime string

	path string

	// es is the elasticsearch database object
	es elasticsearch.Database
)

func assert(err error) {
	if err != nil {
		log.WithFields(log.Fields{
			"plugin":   name,
			"category": category,
			"path":     path,
		}).Fatal(err)
	}
}

// runPdfscan executes the Python PDF analysis script and returns the parsed
// result document (the exact plugins.document.pdf shape the classic engine
// wrote: {"pdfid": {...}, "streams": {...}, "markdown": "..."}). The script
// always emits valid JSON (it catches its own errors), so a non-zero exit is
// tolerated and the stdout is still parsed.
func runPdfscan(ctx context.Context, path string) (map[string]interface{}, error) {
	cmd := exec.CommandContext(ctx, "python3", pyScript, path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		log.WithFields(log.Fields{
			"plugin": name,
			"path":   path,
			"stderr": stderr.String(),
		}).Warnf("pdf analysis exited with error: %v", runErr)
	}

	out := bytes.TrimSpace(stdout.Bytes())
	if len(out) == 0 {
		return map[string]interface{}{
			"error": fmt.Sprintf("pdf produced no output: %v", runErr),
		}, nil
	}

	var results map[string]interface{}
	if jerr := json.Unmarshal(out, &results); jerr != nil {
		return map[string]interface{}{
			"error": "failed to parse pdf JSON output: " + jerr.Error(),
		}, nil
	}
	return results, nil
}

func main() {

	cli.AppHelpTemplate = utils.AppHelpTemplate
	app := cli.NewApp()

	app.Name = "pdf"
	app.Author = "blacktop"
	app.Email = "https://github.com/blacktop"
	app.Version = Version + ", BuildTime: " + BuildTime
	app.Compiled, _ = time.Parse("20060102", BuildTime)
	app.Usage = "Malice PDF Plugin"
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "verbose output",
		},
		cli.BoolFlag{
			Name:  "table, t",
			Usage: "output as Markdown table",
		},
		cli.StringFlag{
			Name:        "elasticsearch",
			Value:       "",
			Usage:       "elasticsearch url for Malice to store results",
			EnvVar:      "MALICE_ELASTICSEARCH_URL",
			Destination: &es.URL,
		},
		cli.IntFlag{
			Name:   "timeout",
			Value:  60,
			Usage:  "malice plugin timeout (in seconds)",
			EnvVar: "MALICE_TIMEOUT",
		},
	}
	app.Action = func(c *cli.Context) error {

		var err error

		if c.Bool("verbose") {
			log.SetLevel(log.DebugLevel)
		}

		if c.Args().Present() {
			path, err = filepath.Abs(c.Args().First())
			assert(err)

			if _, err = os.Stat(path); os.IsNotExist(err) {
				assert(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Int("timeout"))*time.Second)
			defer cancel()

			results, err := runPdfscan(ctx, path)
			assert(err)

			// upsert into Database
			if len(c.String("elasticsearch")) > 0 {
				err := es.Init()
				if err != nil {
					return errors.Wrap(err, "failed to initalize elasticsearch")
				}
				err = es.StorePluginResults(database.PluginResults{
					ID:       utils.Getopt("MALICE_SCANID", utils.GetSHA256(path)),
					Name:     name,
					Category: category,
					Data:     results,
				})
				if err != nil {
					return errors.Wrapf(err, "failed to index malice/%s results", name)
				}
			}

			if c.Bool("table") {
				if md, ok := results["markdown"].(string); ok {
					fmt.Println(md)
				}
			} else {
				// The classic engine stored the markdown in ES but stripped it
				// from the stdout JSON; preserve that behavior.
				jsonOut := make(map[string]interface{}, len(results))
				for k, v := range results {
					if k == "markdown" {
						continue
					}
					jsonOut[k] = v
				}
				out, _ := json.Marshal(jsonOut)
				fmt.Println(string(out))
			}
		} else {
			log.Fatal(fmt.Errorf("Please supply a file to scan with malice/%s", name))
		}
		return nil
	}

	err := app.Run(os.Args)
	assert(err)
}
