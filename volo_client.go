package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"math/big"

	quic "github.com/lucas-clemente/quic-go"
)

const addr = "localhost:4242"

const message = "Frame_00039_textured_hd_t_s_c.obj"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	//go func() { log.Fatal(echoServer()) }()
	err := clientMain()
	if err != nil {
		panic(err)
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil)
	if err != nil {
		return err
	}
	sess, err := listener.Accept(context.Background())
	if err != nil {
		return err
	}
	stream, err := sess.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	dirPath := "objs"
        PthSep := string(os.PathSeparator)
        filepath := dirPath + PthSep + string(message)
	file, err := os.Open(filepath)
	if err != nil {
	    panic(err)
	}
	n, err := io.Copy(stream, file)
	if err != nil {
	    fmt.Println("1")
	    panic(err)
        }
	fmt.Println(n)
	for {
	}
	return err
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	session, err := quic.DialAddr(addr, tlsConf, nil)
	if err != nil {
		return err
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}

	fmt.Printf("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}
        f, err := os.Create(message)
	if err != nil {
		fmt.Println("1")
		panic(err)
	}
	defer f.Close()
	fmt.Println("x")
	n, err := io.Copy(f,stream)
	fmt.Println("y")
	if err != nil {
		fmt.Println("1")
		panic(err)
	}
	fmt.Println("Received:"+string(n))
        fmt.Printf("Finished saving...")
	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int,error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
        return w.Writer.Write(b)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}
