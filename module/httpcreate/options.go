package httpcreate

type Options struct {
	Threads int
	Output  string
	Proxy   string
	Url     string
	File    string
}

func NewOptions() *Options {
	return &Options{}
}
