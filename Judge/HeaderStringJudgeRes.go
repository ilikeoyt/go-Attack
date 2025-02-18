package Judge

import (
	"go-attack-new/ConLoad"
	"net/http"
	"strings"
)

func HeaderStringJudgeRes(rspHeaders http.Header, filename string, randomString string, randomNumber string) bool {
	var matchHeaderStrings []string
	var logic string

	config, err := ConLoad.LoadConfig(filename)
	if err != nil {
		return false
	}

	for _, match := range config.MatchHeaders {
		matchHeaderStrings = match.MatchHeaderStrings
		logic = match.Logic
	}

	for key, value := range matchHeaderStrings {
		matchHeaderStrings[key] = strings.ReplaceAll(value, "${{randomString}}", randomString)
	}

	for key, value := range matchHeaderStrings {
		matchHeaderStrings[key] = strings.ReplaceAll(value, "${{randomNumber}}", randomNumber)
	}

	for rspheader := range rspHeaders {
		if logic == "AND" || logic == "" {
			if containsAll(rspheader, matchHeaderStrings) {
				return true
			}
		} else if logic == "OR" {
			if containsAny(rspheader, matchHeaderStrings) {
				return true
			}
		}
	}
	return false
}
