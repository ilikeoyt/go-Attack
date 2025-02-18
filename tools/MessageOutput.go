package tools

import (
	"fmt"
	"go-attack-new/ConLoad"
)

func MessageOutput(filename string, attackFlag bool, url string) error {
	var Name string
	var payload string

	config, LoadErr := ConLoad.LoadConfig(filename)
	if LoadErr != nil {
		return LoadErr
	}

	for _, match := range config.Info {
		Name = match.Name
	}

	for _, match := range config.Attack {
		payload = match.Payload
	}

	fmt.Println("[*]" + Name + " : " + url)
	if attackFlag {
		fmt.Println(fmt.Sprintf("Attack-Result : %s"+payload+"\n", url))
	}
	return nil
}
