package config

import (
	"errors"
	"fmt"
	"time"
)

type errorsList struct {
	ErrAssertion          error
	ErrTargetEmpty        error
	ErrTaskFailed         error
	ErrPortocolScanFailed error
	ErrPortNotProtocol    error
}

type Application struct {
	SC             string
	PocId          string
	PocTags        string
	FingerMatch    bool
	FingerFile     string
	PocFile        string
	NoPing         bool
	FullScan       bool
	SshKey         string
	Verbose        bool
	FofaQuery      string
	FofaSize       int
	FofaKey        string
	ScanRandom     bool
	HttpProxy      string
	Socks5Proxy    string
	Port           string
	Target         string
	TargetUrl      string
	TargetFile     string
	OutputFileName string
	WorkPoolNum    int

	TLSHandshakeTimeout time.Duration
	WebScanTimeout      time.Duration
	PortScanTimeout     time.Duration
	ICMPTimeOut         time.Duration
}

var application *Application

// 端口
var (
	PortAll         = "1-65535"
	PortDefault     = "7,11,13,15,17,19,20,21,22,23,25,26,30,31,32,36,37,38,43,49,51,53,53,67,67,69,70,79,80,80,81,82,83,84,85,86,87,88,88,89,98,102,104,106,110,111,111,113,113,119,121,123,131,135,137,138,139,143,161,162,175,177,179,199,211,221,222,264,280,311,389,391,427,443,443,444,445,449,465,500,500,502,503,505,512,515,520,523,540,548,554,564,587,620,623,626,631,636,646,666,705,771,777,789,800,801,808,853,873,876,880,888,898,900,901,902,990,992,993,994,995,999,1000,1010,1022,1023,1024,1025,1026,1027,1027,1028,1029,1030,1042,1080,1099,1177,1194,1194,1200,1201,1212,1214,1234,1241,1248,1260,1290,1302,1311,1314,1344,1389,1400,1433,1434,1443,1471,1494,1503,1505,1505,1515,1521,1554,1588,1604,1610,1645,1688,1701,1720,1723,1741,1777,1801,1812,1830,1863,1880,1883,1900,1900,1901,1911,1935,1947,1962,1967,1991,1993,2000,2001,2002,2003,2010,2020,2022,2024,2030,2049,2051,2052,2053,2055,2064,2077,2080,2082,2083,2083,2086,2087,2094,2095,2096,2103,2105,2107,2121,2123,2152,2154,2160,2181,2222,2223,2252,2306,2323,2332,2362,2375,2376,2379,2396,2401,2404,2406,2424,2424,2425,2427,2443,2455,2480,2501,2525,2600,2601,2604,2628,2638,2701,2715,2809,2869,3000,3001,3002,3005,3050,3052,3075,3097,3128,3260,3280,3283,3288,3299,3306,3307,3310,3311,3312,3333,3333,3337,3352,3372,3388,3389,3390,3391,3443,3460,3478,3520,3522,3523,3524,3525,3528,3531,3541,3542,3567,3671,3689,3690,3702,3749,3780,3784,3790,4000,4022,4028,4040,4050,4063,4064,4070,4155,4190,4200,4300,4369,4430,4433,4440,4443,4444,4500,4505,4506,4567,4660,4664,4711,4712,4730,4782,4786,4800,4840,4842,4848,4880,4899,4911,4949,5000,5000,5001,5001,5002,5002,5003,5004,5004,5005,5005,5006,5006,5007,5007,5008,5008,5009,5010,5038,5050,5050,5051,5060,5060,5061,5061,5080,5084,5093,5094,5095,5111,5222,5236,5258,5269,5280,5351,5353,5357,5400,5405,5427,5432,5439,5443,5550,5554,5555,5560,5577,5598,5631,5632,5672,5673,5678,5683,5701,5800,5801,5802,5820,5873,5900,5901,5902,5903,5938,5984,5985,5986,6000,6001,6002,6002,6003,6003,6004,6005,6006,6006,6007,6008,6009,6010,6060,6060,6068,6080,6082,6103,6346,6363,6379,6443,6488,6502,6544,6560,6565,6581,6588,6590,6600,6664,6665,6666,6667,6668,6669,6697,6699,6780,6782,6868,6881,6900,6969,6998,7000,7000,7001,7001,7002,7003,7003,7004,7005,7005,7007,7010,7014,7070,7071,7077,7080,7100,7144,7145,7170,7171,7180,7187,7199,7272,7288,7382,7401,7402,7443,7474,7479,7493,7500,7537,7547,7548,7634,7657,7676,7776,7777,7778,7779,7780,7788,7911,8000,8001,8002,8002,8003,8004,8005,8006,8007,8008,8009,8010,8020,8025,8030,8032,8040,8058,8060,8069,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8111,8112,8118,8123,8125,8126,8129,8138,8139,8140,8159,8161,8181,8182,8194,8200,8211,8222,8291,8332,8333,8334,8351,8377,8378,8388,8443,8444,8480,8500,8529,8545,8546,8554,8567,8600,8649,8686,8688,8728,8729,8765,8800,8834,8848,8880,8881,8882,8883,8884,8885,8886,8887,8888,8888,8889,8890,8899,8983,8999,9000,9000,9001,9002,9003,9004,9005,9006,9007,9008,9009,9010,9011,9012,9030,9042,9050,9051,9080,9083,9090,9091,9092,9093,9100,9100,9108,9151,9191,9200,9229,9292,9295,9300,9306,9333,9334,9418,9443,9444,9446,9527,9530,9595,9600,9653,9668,9700,9711,9801,9864,9869,9870,9876,9943,9944,9981,9997,9999,10000,10000,10001,10001,10003,10005,10030,10035,10162,10243,10250,10255,10332,10333,10389,10443,10554,10909,10911,10912,11001,11211,11211,11300,11310,11371,11965,12000,12300,12345,12999,13579,13666,13720,13722,14000,14147,14265,14443,14534,15000,16000,16010,16030,16922,16923,16992,16993,17000,17185,17988,18000,18001,18080,18081,18086,18245,18246,18264,19150,19888,19999,20000,20000,20002,20005,20201,20202,20332,20547,20880,22105,22222,22335,23023,23424,25000,25010,25105,25565,26214,26257,26470,27015,27015,27016,27017,28015,28017,28080,28784,29876,29999,30001,30005,30303,30310,30311,30312,30313,30718,31337,32400,32412,32414,32768,32769,32770,32771,32773,33338,33848,33890,34567,34599,34962,34963,34964,37020,37215,37777,37810,40000,40001,41795,42873,44158,44818,44818,45554,47808,48899,49151,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49664,49665,49666,49667,49668,49669,49670,49671,49672,49673,49674,50000,50050,50060,50070,50075,50090,50100,50111,51106,52869,53413,54321,55442,55553,55555,59110,60001,60010,60030,60443,61222,61613,61616,62078,64738,64738"
	PortSql         = "523,1433,1434,1521,1583,2100,2049,2638,3050,3306,3351,5000,5432,5433,5601,5984,6082,6379,7474,8080,8088,8089,8098,8471,9000,9160,9200,9300,9471,11211,11211,15672,19888,27017,27019,27080,28017,50000,50070,50090"
	PortCompany     = "21,22,23,25,53,53,69,80,81,88,110,111,111,123,123,135,137,139,161,177,389,427,443,445,465,500,515,520,523,548,623,626,636,873,902,1080,1099,1433,1434,1521,1604,1645,1701,1883,1900,2049,2181,2375,2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379,6900,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,11211,27017,33848,37777,50000,50070,61616"
	PortSmall       = "21,22,80,137,139,161,443,445,1900,3306,3389,5353,8080"
	PortGroupMapNew = map[int]string{
		21:    "ftp",
		22:    "ssh",
		25:    "smtp",
		135:   "netbios",
		137:   "netbios",
		139:   "netbios",
		389:   "ldap",
		445:   "smb",
		1433:  "mssql",
		1521:  "oracle",
		2222:  "ssh",
		3306:  "mysql",
		3389:  "rdp",
		5432:  "psql",
		5900:  "vnc",
		6379:  "redis",
		9000:  "fcgi",
		9200:  "elaticsearch",
		11211: "mem",
		27017: "mgo",
	}
)

// 错误
var (
	Errors                *errorsList
	errAssertion          = errors.New("工人函数断言错误")
	errTargetEmpty        = errors.New("目标为空")
	errTaskFailed         = errors.New("任务执行失败")
	errPortocolScanFailed = errors.New("全协议扫描失败")
	errPortNotProtocol    = errors.New("端口号没有对应的协议")
)

// 私有全局变量
var (
	sC             string
	pocId          string
	pocTags        string
	fingerMatch    bool
	fingerFile     string
	pocFile        string
	noPing         bool
	fullScan       bool
	sshKey         string
	verbose        bool
	FofaQuery      string
	FofaSize       int
	FofaKey        string
	scanRandom     bool
	httpProxy      string
	socks5Proxy    string
	port           string
	target         string
	targetUrl      string
	targetFile     string
	outputFileName string
	workPoolNum    int

	PortScanTimeout = 3 * time.Second
)

// Get 获取配置
func Get() *Application {
	if application != nil {
		return application
	}
	application = &Application{
		SC:                  sC,
		PocId:               pocId,
		PocTags:             pocTags,
		FingerFile:          fingerFile,
		FingerMatch:         fingerMatch,
		PocFile:             pocFile,
		NoPing:              noPing,
		FullScan:            fullScan,
		SshKey:              sshKey,
		Verbose:             verbose,
		FofaQuery:           FofaQuery,
		FofaSize:            FofaSize,
		FofaKey:             FofaKey,
		ScanRandom:          scanRandom,
		HttpProxy:           httpProxy,
		Socks5Proxy:         socks5Proxy,
		Port:                port,
		Target:              target,
		TargetUrl:           targetUrl,
		TargetFile:          targetFile,
		OutputFileName:      outputFileName,
		WorkPoolNum:         workPoolNum,
		TLSHandshakeTimeout: 8 * time.Second,
		WebScanTimeout:      10 * time.Second,
		PortScanTimeout:     3 * time.Second,
		ICMPTimeOut:         2 * time.Second,
	}
	return application
}

func (c *Application) CheckProxy() bool {
	if c.Socks5Proxy != "" || c.HttpProxy != "" {
		return true
	}
	return false
}

func (c *Application) PrintDefaultUsage() {
	fmt.Println(Logo)
	fmt.Println("---------------GettingTarget----------")
	fmt.Println("---------------Config-----------------")
	fmt.Printf("threads: %d\n", c.WorkPoolNum)
	fmt.Printf("no-ping: %t\n", c.NoPing)
	if c.OutputFileName != "" {
		fmt.Printf("output file: %s\n", c.OutputFileName)
	} else {
		fmt.Printf("output file: %s\n", "Null")
	}
	if c.Socks5Proxy == "" && c.HttpProxy == "" {
		fmt.Printf("proxy addr: %s\n", "Null")
	}
	if c.HttpProxy != "" {
		fmt.Printf("proxy addr: %s\n", c.HttpProxy)
	}
	if c.Socks5Proxy != "" {
		fmt.Printf("proxy addr: %s\n", c.Socks5Proxy)
	}
	fmt.Printf("scan-random: %t\n", c.ScanRandom)
}

func GetErrors() *errorsList {
	if Errors != nil {
		return Errors
	}
	Errors = &errorsList{
		ErrAssertion:          errAssertion,
		ErrTargetEmpty:        errTargetEmpty,
		ErrTaskFailed:         errTaskFailed,
		ErrPortocolScanFailed: errPortocolScanFailed,
		ErrPortNotProtocol:    errPortNotProtocol,
	}
	return Errors
}
