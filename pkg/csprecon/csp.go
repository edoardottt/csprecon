package csprecon

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

func checkCSP(url string, client *http.Client) ([]string, error) {
	return get(url, client)
}

func get(url string, client *http.Client) ([]string, error) {
	result := []string{}
	resp, err := client.Get(url)

	if err != nil {
		return result, nil
	}

	body, err := ioutil.ReadAll(resp.Body)

	if resp != nil {
		defer resp.Body.Close()
	}

	headerCSP := resp.Header.Get("Content-Security-Policy")

	fmt.Println(headerCSP)
	fmt.Println(string(body))

	return []string{}, nil
}

func customClient(timeout int) *http.Client {
	//ref: Copy and modify defaults from https://golang.org/src/net/http/transport.go
	//Note: Clients and Transports should only be created once and reused
	transport := http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			// Modify the time to wait for a connection to establish
			Timeout:   time.Duration(timeout) * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	client := http.Client{
		Transport: &transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	return &client
}
