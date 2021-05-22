package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"crypto/tls"
	"net"
	"net/http/httputil"
	"net/http"
	"strings"
	"time"
	"fmt"
	"sync"
	"os/exec"
	"github.com/itchio/go-brotli/dec"
	"github.com/itchio/go-brotli/enc"
)

var ConID int
var dumpnr int
var ApprovedSenders []string

var Certificates map[string]*tls.Certificate
var CerticitateLock sync.Mutex
var TLSconfig *tls.Config

var userscripts map[string]string


var BlockGoogleVideo bool

func HandleHTTPClient(Sc *httputil.ServerConn, ThisClient int, ClientId string, Scheme string) {

	HasConnected := false
	var ServerConnection *httputil.ClientConn


	defer Sc.Close()
	for {

		//Wait untill the client sends a new request
		r, err := Sc.Read()
		//Client closed the conenction
		if err != nil {
			return
		}
		//fix difrences in incoming and outgoing http.Request
		r.RequestURI = ""
		r.URL.Host = r.Host
		r.URL.Scheme = Scheme

		FullUl := r.URL.String()
		reqest_type := r.Header.Get("Content-Type")
		//block := false
		log.Println(" URL ", FullUl, reqest_type, r.URL.Path)

		script_file, has_script_for_host := userscripts[r.URL.Host]

		if r.URL.Path == "/injection_script.js" {
			log.Println("returning script")
			script_src, err := ioutil.ReadFile("userscripts/"+script_file)
			if err != nil {
				log.Fatal("could not open script file", err)
			}
			resp := &http.Response{
				Status:        "200 OK",
				StatusCode:    200,
				ContentLength: int64(len(script_src)),
				Body:          ioutil.NopCloser(bytes.NewReader(script_src)),
				Proto:         "HTTP/1.1",
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				Close:         false,
			}
			resp.Header.Set("Content-Type", "text/html")
			Sc.Write(r, resp)
			continue
		}

		//Infotext := "You tried to download: '" + FullUl + "'.\n"

		if HasConnected == false {
			HasConnected = true

			DestinationAddress := r.URL.Host + ":" + r.URL.Scheme
			NetServerConnection, err := net.Dial("tcp", DestinationAddress)
			if err != nil {
				log.Println("could not connect to server:", DestinationAddress, err)
				return
			}
			if Scheme == "https" {
				TlsConenction := tls.Client(NetServerConnection, TLSconfig)
				ServerConnection = httputil.NewClientConn(TlsConenction, nil)
			} else {
				ServerConnection = httputil.NewClientConn(NetServerConnection, nil)
			}
			defer ServerConnection.Close()
		}

		req_body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Fatal(err)
		}
		r.Body = ioutil.NopCloser(bytes.NewReader(req_body))

		//Lets get the stuff from our server
		resp, err := ServerConnection.Do(r)
		if err != nil && err != httputil.ErrPersistEOF {
			log.Println("Server did not answer nicly on our request:", r.URL.Host, err)
			return
		}

		if has_script_for_host {

			response_type := resp.Header.Get("Content-Type")

			response_body_encoding := resp.Header.Get("Content-Encoding")
			if response_body_encoding == "br" {//decode br if needed
				resp.Body = dec.NewBrotliReader(resp.Body)
			}

			response_body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Fatal(err)
			}
			if strings.Contains(response_type, "text/html") {
				log.Println("inserting script")
				body_txt := string(response_body)
				fixed_body := strings.Replace(body_txt, "<head>", "<head><script src=\"/injection_script.js\"></script>", 1)
				response_body = []byte(fixed_body)
			}
			resp.Body = ioutil.NopCloser(bytes.NewReader(response_body))
			resp.ContentLength = int64(len(response_body))

			if response_body_encoding == "br" {//Encoding as br if needed
				resp.Header.Del("Content-Length")
				compressed_output, _ := enc.CompressBuffer(response_body, &enc.BrotliWriterOptions{Quality: 1})
				resp.Body = ioutil.NopCloser(bytes.NewReader(compressed_output))
				resp.ContentLength = int64(len(compressed_output))
			}
		}
		Sc.Write(r, resp)
	}
}

type ConenctionHandler func(*net.TCPConn, int)

/*
 httpConHandler creates a HTTP conenction from a tcp conenction
*/
func httpConHandler(TcpConnection *net.TCPConn, ConID int) {

	//Handle Http stuff
	HttpReader := httputil.NewServerConn(TcpConnection, nil)
	HandleHTTPClient(HttpReader, ConID, TcpConnection.RemoteAddr().String(), "http")
}


/*
 TLSConHandler creates a HTTP conenction from a tls tcp conenction
*/
func TLSConHandler(TcpConnection *net.TCPConn, ConID int) {


	//Apply tls encryption
	TlsConenction := tls.Server(TcpConnection, TLSconfig)

	//Handle Http stuff
	HttpReader := httputil.NewServerConn(TlsConenction, nil)
	HandleHTTPClient(HttpReader, ConID, TcpConnection.RemoteAddr().String(), "https")
}


func AcceptConenctions(NetworkListener *net.TCPListener, TcpHandler ConenctionHandler) {
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		//Accept new conenctions and handle errors they may cause
		TcpConnenction, e := NetworkListener.AcceptTCP()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			panic(e)
		}
		tempDelay = 0
		//Give the connection away to a gorutine that will handle it
		ConID++
		go TcpHandler(TcpConnenction, ConID)
	}
}

func GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error){
	if strings.Contains(clientHello.ServerName, "icloud.com") || strings.Contains(clientHello.ServerName, "apple.com") {
		return nil, fmt.Errorf("cant provide certs for icloud")
	}
	CerticitateLock.Lock()
	defer CerticitateLock.Unlock()
	log.Println(ConID, "GetCertificate", clientHello.ServerName)
	if Certificates[clientHello.ServerName] != nil{
		return Certificates[clientHello.ServerName], nil
	}
	workingdir, _ := os.Getwd()
	cmd := exec.Command(workingdir+"/create_certificate.sh", clientHello.ServerName)
	cmd.CombinedOutput()
	home := os.Getenv("HOME")
	cert, err := tls.LoadX509KeyPair(home+"/.mitmproxy/certs/"+clientHello.ServerName+".crt", home+"/.mitmproxy/certs/superkey.key")
	Certificates[clientHello.ServerName] = &cert
	return &cert, err

}
func main() {
	BlockGoogleVideo = false
	ConID = 0
	dumpnr = 0
	ApprovedSenders = []string{}
	userscripts = map[string]string{
		"www.youtube.com": "youtube.ads.skip2.user.js",
	}

	Certificates = make(map[string]*tls.Certificate)

	/*
	Open Listener for http conenctions
	*/
	HttpSocketAddress, _ := net.ResolveTCPAddr("tcp", ":8191")
	HttpSocket, err := net.ListenTCP("tcp", HttpSocketAddress)
	if err != nil {
		panic(err)
	}
	defer HttpSocket.Close()
	go AcceptConenctions(HttpSocket, httpConHandler)

	//Load The Cert
	TLSconfig = &tls.Config{}
	TLSconfig.NextProtos = []string{"http/1.1"}
	TLSconfig.InsecureSkipVerify = true
	TLSconfig.GetCertificate = GetCertificate
	if err != nil {
		panic(err)
	}

	/*
	Open Listener for https conenctions
	*/

	HttpsSocketAddress, _ := net.ResolveTCPAddr("tcp", ":8190")
	HttpsSocket, err := net.ListenTCP("tcp", HttpsSocketAddress)
	if err != nil {
		panic(err)
	}
	defer HttpsSocket.Close()
	AcceptConenctions(HttpsSocket, TLSConHandler)

}
