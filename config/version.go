package config

import (
	"github.com/polite007/Milkyway/pkg/color"
)

var (
	Version = "milkyway version: 0.1.0"
)

var (
	Logo = color.Yellow(`
           _ _ _                              
 _ __ ___ (_) | | ___   ___      ____ _ _   _ 
| '_ ' _ \| | | |/ / | | \ \ /\ / / _'' | | | |
| | | | | | | |   <| |_| |\ V  V / (_| | |_| |
|_| |_| |_|_|_|_|\_\\__, | \_/\_/ \__,_|\__, |
                    |___/               |___/ 
`+
		"\n                                 ") + Version + "\n" + "--------------------------------------\n" +
		"https://github.com/polite-007/Milkyway\n" + "--------------------------------------"
)

var (
	Name = "Milkyway"
)
