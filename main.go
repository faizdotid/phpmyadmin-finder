package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	var (
		urls    multiFlag
		file    string
		threads int
		timeout int
		output  string
		debug   bool
	)

	flag.Var(&urls, "u", "single URL to scan (repeatable)")
	flag.Var(&urls, "url", "single URL to scan (repeatable)")
	flag.StringVar(&file, "f", "", "file containing target URLs")
	flag.StringVar(&file, "file", "", "file containing target URLs")
	flag.IntVar(&threads, "t", 20, "number of concurrent workers")
	flag.IntVar(&threads, "threads", 20, "number of concurrent workers")
	flag.IntVar(&timeout, "timeout", 10, "request timeout in seconds")
	flag.StringVar(&output, "o", "", "output file")
	flag.StringVar(&output, "output", "", "output file")
	flag.BoolVar(&debug, "d", false, "enable debug logging")
	flag.BoolVar(&debug, "debug", false, "enable debug logging")
	flag.Parse()

	if threads <= 0 {
		fmt.Fprintln(os.Stderr, "error: threads must be > 0")
		os.Exit(2)
	}
	if timeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: timeout must be > 0")
		os.Exit(2)
	}

	targets := []string(urls)
	if file != "" {
		loaded, err := loadURLs(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read %s: %v\n", file, err)
			os.Exit(1)
		}
		targets = append(targets, loaded...)
	}

	if len(targets) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	initColor()

	scanner := newScanner(targets, threads, time.Duration(timeout)*time.Second, output, debug)
	found := scanner.Run()
	fmt.Printf("\nFound %d panel(s)\n", found)
}

func loadURLs(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}
