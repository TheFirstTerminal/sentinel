// csiceval measures Sentinel on the CSIC 2010 HTTP dataset: how many of its
// 25,065 attacks each layer catches, and how many of its 36,000 normal test
// requests it wrongly flags.
//
//	go run ./cmd/csiceval -csic /path/to/csic2010 [-crs /path/to/coreruleset/rules] [-model file]
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"sentinel/gateway/internal/ml"
	"sentinel/gateway/internal/ml/csic"
)

func main() {
	dir := flag.String("csic", "", "folder with the CSIC 2010 files")
	crsDir := flag.String("crs", "", "OWASP CRS rules/ folder (optional)")
	modelFile := flag.String("model", "", "ML model JSON (default: the built-in one)")
	flag.Parse()
	normal, err := csic.Load(filepath.Join(*dir, "normalTrafficTest.txt"), false)
	check(err)
	attacks, err := csic.Load(filepath.Join(*dir, "anomalousTrafficTest.txt"), true)
	check(err)
	m := loadModel(*modelFile)
	train, err := csic.Load(filepath.Join(*dir, "normalTrafficTraining.txt"), false)
	check(err)
	res := csic.EvaluateWithProfile(normal, attacks, m, *crsDir, csic.LearnProfile(train))
	fmt.Print(res)
}

func loadModel(file string) *ml.Model {
	if file == "" {
		m, err := ml.Default()
		check(err)
		return m
	}
	data, err := os.ReadFile(file)
	check(err)
	m, err := ml.Parse(data)
	check(err)
	return m
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
