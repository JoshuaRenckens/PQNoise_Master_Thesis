package main

import (
	"fmt"
	"net"
	"time"
	//"crypto/rand"
	
	//"gitlab.com/yawning/nyquist.git/seec"
	"gitlab.com/yawning/nyquist.git"
)

func main() {
    protocol, err := nyquist.NewProtocol("Noise_pqXN_Kyber512_ChaChaPoly_BLAKE2s")

    //seecGenRand, err := seec.GenKeyPRPAES(rand.Reader, 256)
    
    //bobStatic, err := protocol.KEM.GenerateKeypair(seecGenRand)
    
    bobCfg := &nyquist.HandshakeConfig{
	Protocol: protocol,
	KEM: &nyquist.KEMConfig{
		//LocalStatic: bobStatic,
	},
	// SEECGenKey is optional, and just using the raw entropy
	// device is supported.
	IsInitiator: false,
    }
    bobHs, err := nyquist.NewHandshake(bobCfg)
    fmt.Println(bobCfg.Protocol.String())
    
    // Listen for incoming connections on port 8080
    fmt.Println("Waiting for connection")
    ln, err := net.Listen("tcp", ":8888")
    if err != nil {
        fmt.Println(err)
        return
    }

    // Accept incoming connections and handle them
    for {
        conn, err := ln.Accept()
        if err != nil {
            fmt.Println(err)
            continue
        }
        fmt.Println("Connected")

        //_, err = conn.Write(bobStatic.Public().Bytes())
        
        buf := make([]byte, 800)
        buf2 := make([]byte, 832)
        
        what, err1 := conn.Read(buf)
        if err1 != nil {
            fmt.Println(err)
            return
        }
        
        fmt.Println(what)
        
        bobHs.ReadMessage(nil, buf)
        
        fmt.Println("Received message 1")
	
	start := time.Now()
	bobMsg1, err := bobHs.WriteMessage(nil, nil) // (bob) -> ekem
	elapsed := time.Since(start)
	
	_, err = conn.Write(bobMsg1)
	
	fmt.Println(elapsed)
	fmt.Println("Sent message 2")

	
	_, err2 := conn.Read(buf2)
        if err2 != nil {
            fmt.Println(err)
            return
        }
	
	bobHs.ReadMessage(nil, buf2)
	
	fmt.Println("Received message 3")

	start = time.Now()
	bobMsg2, err := bobHs.WriteMessage(nil, nil) // (bob) -> skem
	elapsed = time.Since(start)
	
	fmt.Println(err)
	
	_, err = conn.Write(bobMsg2)
	
	fmt.Println(elapsed)
	fmt.Println("Sent message 4")
	
	conn.Close()
        
    }
}
