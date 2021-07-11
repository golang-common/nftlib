// +build linux

package nftlib

import "encoding/json"

func IndentJson(obj interface{}) string {
	ret, err := json.MarshalIndent(obj, "", "\t")
	if err != nil {
		return err.Error()
	}
	return string(ret)
}
