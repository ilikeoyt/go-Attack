package Judge

import (
	"fmt"
	"go-attack-new/ConLoad"
	"time"
)

func TimeJudgeRes(rspTime time.Duration, url string, attackFlag bool, filename string) error {
	var Name string
	var payload string
	var LesTime int
	var MaxTime int

	config, err := ConLoad.LoadConfig(filename)
	if err != nil {
		return err
	}

	for _, match := range config.Info {
		Name = match.Name
	}

	for _, match := range config.Match {
		LesTime = match.LesTime
		MaxTime = match.MaxTime
	}

	for _, match := range config.Attack {
		payload = match.Payload
	}

	if time.Duration(LesTime)*time.Second <= rspTime && rspTime <= time.Duration(MaxTime)*time.Second {
		fmt.Println("[*]" + Name + " : " + url)
		if attackFlag {
			fmt.Println(fmt.Sprintf("Attack-Result : %s"+payload+"\n", url))
		}
	}
	return nil
}
