package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/google/shlex"
)

func tracerouteTryExecute(cmd []string, args [][]string) ([]byte, string) {
	var output []byte
	var errString = ""
	for i := range cmd {
		var err error
		var cmdCombined = cmd[i] + " " + strings.Join(args[i], " ")

		instance := exec.Command(cmd[i], args[i]...)
		output, err = instance.CombinedOutput()
		if err == nil {
			return output, ""
		}
		errString += fmt.Sprintf("+ (Try %d) %s\n%s\n\n", (i + 1), cmdCombined, output)
	}
	return nil, errString
}

func tracerouteHandler(httpW http.ResponseWriter, httpR *http.Request) {
	query := string(httpR.URL.Query().Get("q"))
	query = strings.TrimSpace(query)

	if query == "" {
		invalidHandler(httpW, httpR)
	} else {
		args, err := shlex.Split(query)
		if err != nil {
			httpW.WriteHeader(http.StatusInternalServerError)
			httpW.Write([]byte(fmt.Sprintf("failed to parse args: %s\n", err.Error())))
			return
		}

		hostname_idx := -1
		for i, arg := range args {
			switch {
				case arg == "-4":
					continue
				case arg == "-6":
					continue
				case strings.HasPrefix(arg, "-"):
					httpW.WriteHeader(http.StatusInternalServerError)
					httpW.Write([]byte(fmt.Sprintf("arg now allowed: %s\n", arg)))
					return
				default:
					if hostname_idx != -1 {
						httpW.WriteHeader(http.StatusInternalServerError)
						httpW.Write([]byte(fmt.Sprintf("arg now allowed: %s\n", arg)))
						return
					} else {
						matched, _ := regexp.MatchString("^[a-zA-Z0-9-.]{1,254}$", arg)
						if !matched {
							httpW.WriteHeader(http.StatusInternalServerError)
							httpW.Write([]byte(fmt.Sprintf("incorrect domain name: %s\n", arg)))
							return
						}
						hostname_idx = i
					}
			}
		}

		var result []byte
		var errString string
		skippedCounter := 0

		if runtime.GOOS == "freebsd" || runtime.GOOS == "netbsd" || runtime.GOOS == "openbsd" {
			result, errString = tracerouteTryExecute(
				[]string{
					setting.tr_bin,
					setting.tr_bin,
				},
				[][]string{
					append([]string{"-q1", "-w1"}, args...),
					args,
				},
			)
		} else if runtime.GOOS == "linux" {
			result, errString = tracerouteTryExecute(
				[]string{
					setting.tr_bin,
					setting.tr_bin,
					setting.tr_bin,
				},
				[][]string{
					append([]string{"-q1", "-N32", "-w1"}, args...),
					append([]string{"-q1", "-w1"}, args...),
					args,
				},
			)
		} else {
			httpW.WriteHeader(http.StatusInternalServerError)
			httpW.Write([]byte("traceroute not supported on this node.\n"))
			return
		}
		if errString != "" {
			httpW.WriteHeader(http.StatusInternalServerError)
			httpW.Write([]byte(errString))
		}
		if result != nil {
			if setting.tr_raw {
				httpW.Write(result)
			} else {
				errString = string(result)
				errString = regexp.MustCompile(`(?m)^\s*(\d*)\s*\*\n`).ReplaceAllStringFunc(errString, func(w string) string {
					skippedCounter++
					return ""
				})
				httpW.Write([]byte(strings.TrimSpace(errString)))
				if skippedCounter > 0 {
					httpW.Write([]byte("\n\n" + strconv.Itoa(skippedCounter) + " hops not responding."))
				}
			}
		}
	}
}
