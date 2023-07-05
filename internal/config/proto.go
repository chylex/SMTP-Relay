package config

import "strings"

type ProtoAddr struct {
	Protocol string
	Address  string
}

func splitProto(s string) ProtoAddr {
	idx := strings.Index(s, "://")
	if idx == -1 {
		return ProtoAddr{
			Address: s,
		}
	} else {
		return ProtoAddr{
			Protocol: s[0:idx],
			Address:  s[idx+3:],
		}
	}
}
