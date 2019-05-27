package main

import (
	"fmt"
	// "errors"
	"flag"
	"net/http"
	"net/url"
	// "os"
	"regexp"
	"strings"
	"io/ioutil"
	"crypto/tls"
	"encoding/json"
)

type Scanner struct {
	scout string
	find string
}

type Response struct {
	Body string
	StatusCode int
	ContentLength int
}

type ScanRes struct {
	Vuln bool
	Result string //漏洞证明
	StatusCode int
	Error string
}


var XSS_PATTERNS = map[string][]string{
            `<script[^>]*>[^<]*?'[^<']*%s[^<']*'[^<]*</script>`: {`'`, `;`} , //<script> '' </script>
			`<script[^>]*>[^<]*?"[^<"]*%s[^<"]*"[^<]*</script>`:{`"`,`;`}, //<script> "" </script>
			`<script[^>]*>[^<]*?%s[^<]*</script>`: {`;`}, //<script> </script>
			`>[^<]*%s[^<]*<`:{}, //> <
			`<[^>]*'[^>']*%s[^>']*'[^>]*>`:{`'`}, //< ''>
			`<[^>]*"[^>"]*%s[^>"]*"[^>]*>`:{`"`}, //< "" >
			`<[^>]*%s[^>]*>`:{}, // <  >
			`^%s(.*);`:{`<`,`>`}, //jsonp
}

var cookie = flag.String("c","","-c Cookie")
var target = flag.String("t","","-t Url")
var method = flag.String("m", "G", "-m RequestMethod")
var parama = flag.String("p","","-p Parama")
var help = flag.Bool("h",false,"-h print Usage")

func main() {
	flag.Parse()
	if *help{
		fmt.Println("\t-c cookie\n\t-t target\n\t-m RequestMethod\n\t-p parama")
		return
	}

	scan_task := new(Scanner)
	scan_task.Initial()
	result:= scan_task.Scan_xss(*target, *parama, *method)

	data,_ := json.Marshal(result)

	fmt.Println(string(data))


}

func (scanner *Scanner) Initial() {
	scanner.scout = `Autoscanxss'"<>;Z`  //探测特殊字符
	scanner.find = `Autoscanxss['"<>;]+Z`
}

func (scanner *Scanner) Receive_g(Url string,data string) (*Response,error ) {
	Resp := new(Response) //响应
	client := &http.Client{}

	//代理，检测发包
	urli := url.URL{}
    urlproxy, _ := urli.Parse("http://127.0.0.1:8080")
	client.Transport = &http.Transport{
		TLSClientConfig:&tls.Config{
			InsecureSkipVerify:true,
		},
        Proxy: http.ProxyURL(urlproxy),
	}

	req,err := http.NewRequest("GET", fmt.Sprintf("%s?%s", Url,data),strings.NewReader(""))
	if err != nil {
		return nil,err
	}

	req.Header.Set("Cookie", *cookie)
	req.Header.Set("User-Agent", "duapp/3.6.0(android;9)")
	resp,err := client.Do(req)
	if err != nil {
		return nil,err
	}

	defer resp.Body.Close()

	var b []byte
	if b,err = ioutil.ReadAll(resp.Body);err != nil{
		Resp.Body = string(b)
		return Resp,err
	}

	Resp.ContentLength = len(b)
	Resp.Body = string(b)

	Resp.StatusCode = resp.StatusCode
	return Resp,nil
}


func (scanner *Scanner) Receive_p(url string,data string) (*Response,error) {
	Resp := new(Response)

	client := &http.Client{}
	client.Transport = &http.Transport{
		TLSClientConfig:&tls.Config{
			InsecureSkipVerify:true,
		},
	}

	req,err := http.NewRequest("Post", url, strings.NewReader(data))
	if err != nil {
		return nil,err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Cookie", *cookie)
	req.Header.Set("User-Agent", "duapp/3.6.0(android;9)")
	resp, err := client.Do(req)
	defer resp.Body.Close()
	var b []byte
	if b, err = ioutil.ReadAll(resp.Body); err != nil {
		// fmt.Println(err)
		return nil, err
	}
	Resp.ContentLength = len(b)
	Resp.Body = string(b)
	Resp.StatusCode = resp.StatusCode
	return Resp,nil
}


//临时，后续改为签名包调用
func getSign() string {
	return "sign=xxx&newSign=xxx"
}

func (scanner *Scanner) Scan_xss(Url string,data string,method string) *ScanRes {
	result := new(ScanRes)
	resp := new(Response)
	var err error

	if Url == "" || data == ""{
		result.Result = ""
		result.StatusCode = 0
		result.Vuln = false
		result.Error = "no url or parama"
		return result
	}

	var payload string
	for _,parama := range strings.Split(data, " "){
		payload = payload + parama + "=" +scanner.scout+"&"
	}

	payload =  url.PathEscape(payload + getSign())
	// fmt.Println(payload)

	if method=="G"{
		resp,err = scanner.Receive_g(Url, payload)
		
	} else{
		resp,err = scanner.Receive_p(Url, payload)
	}

	if err != nil {
			// result.StatusCode = 0
			result.Error = string(err.Error())
			return result
		}

	if resp.StatusCode != 200 {
			result.StatusCode = resp.StatusCode
			result.Error = "ResponseCode Not 200"
			return result
	}
//检测
	var context string
	result.StatusCode = resp.StatusCode
	for regex_pattern,need := range XSS_PATTERNS{
		re := regexp.MustCompile(fmt.Sprintf(regex_pattern, scanner.find))
		context = re.FindString(resp.Body)
		if context != ""{
			fmt.Println("context",context)
			//构造payload所需字符未被过滤？
			var flag = true
			for _,ndchar := range need{
				if strings.Index(context, ndchar) == -1 {
					flag = false
				}
			}
			if flag{
				fmt.Println("find xss ",context)
				result.Result = context
				result.Vuln = true
				result.Error = ""
				fmt.Println("result.Vuln", result.Vuln)
				return result
			}

			
		}
	}


	return result

	
}

