package ConLoad

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
)

type RequestConfig struct {
	ReqPath    string            `yaml:"ReqPath"`
	Timeout    int               `yaml:"timeout"`
	HttpMethod string            `yaml:"httpMethod"`
	Headers    map[string]string `yaml:"Headers"`
	Data       string            `yaml:"data"`
}

type MatchConfig struct {
	Type         string   `yaml:"type"`
	MatchStrings []string `yaml:"matchStrings"` // 支持多个匹配字符串
	Logic        string   `yaml:"logic"`
	LesTime      int      `yaml:"lesTime"`
	MaxTime      int      `yaml:"maxTime"`
}

type InfoConfig struct {
	Name string `yaml:"name"`
	CVE  string `yaml:"CVE"`
	CNVD string `yaml:"CNVD"`
}

type AttackConfig struct {
	Payload string `yaml:"payload"`
}

type ParamConfig struct {
	RandomString int `yaml:"randomString"`
	RandomNumber int `yaml:"randomNumber"`
}

type MatchHeadersConfig struct {
	MatchOnlyHeaders   string   `yaml:"matchOnlyHeaders"`
	MatchHeaderStrings []string `yaml:"matchHeaderStrings"`
	Logic              string   `yaml:"logic"`
}

type Config struct {
	Requests     []RequestConfig      `yaml:"requests"`
	Match        []MatchConfig        `yaml:"match"`
	Info         []InfoConfig         `yaml:"info"`
	Attack       []AttackConfig       `yaml:"attack"`
	Param        []ParamConfig        `yaml:"param"`
	MatchHeaders []MatchHeadersConfig `yaml:"matchHeaders"`
}

func LoadConfig(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
