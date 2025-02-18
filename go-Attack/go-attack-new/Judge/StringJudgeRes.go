package Judge

import (
	"go-attack-new/ConLoad"
	"strings"
)

func StringJudgeRes(resBody string, filename string, randomString string, randomNumber string) bool {
	var MatchStrings []string
	var logic string

	config, LoadErr := ConLoad.LoadConfig(filename)
	if LoadErr != nil {
		return false
	}

	for _, match := range config.Match {
		MatchStrings = match.MatchStrings
		logic = match.Logic
	}

	for key, value := range MatchStrings {
		MatchStrings[key] = strings.ReplaceAll(value, "${{randomString}}", randomString)
	}

	for key, value := range MatchStrings {
		MatchStrings[key] = strings.ReplaceAll(value, "${{randomNumber}}", randomNumber)
	}

	if logic == "AND" || logic == "" {
		if containsAll(resBody, MatchStrings) {
			return true
		}
	} else if logic == "OR" {
		if containsAny(resBody, MatchStrings) {
			return true
		}
	}
	return false
}

func containsAll(str string, arr []string) bool {
	for _, s := range arr {
		if !strings.Contains(str, s) { // 如果字符串不包含 arr 中的某个元素，直接返回 false
			return false
		}
	}
	return true // 如果全部包含，返回 true
}

func containsAny(str string, arr []string) bool {
	for _, s := range arr {
		if strings.Contains(str, s) {
			return true // 只要有一个匹配，返回 true
		}
	}
	return false // 如果没有匹配的，返回 false
}
