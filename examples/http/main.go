// An HTTP server reachable only inside the EasyTier overlay.
package main

import (
	"context"
	"log"
	"net/http"
	"net/netip"

	easytier "github.com/easytier/easytier-go"
)

func main() {
	s, err := easytier.New(easytier.Config{
		NetworkName: "example", NetworkSecret: "replace-me", Hostname: "web",
		IPv4:       netip.MustParsePrefix("10.42.0.1/24"),
		Listeners:  []string{"tcp://127.0.0.1:21110"},
		Encryption: easytier.Noise,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	if err = s.Up(context.Background()); err != nil {
		log.Print(err)
		return
	}
	listener, err := s.Listen("tcp", ":8080")
	if err != nil {
		log.Print(err)
		return
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello from web.et.net\n")) })
	if err = http.Serve(listener, handler); err != nil {
		log.Print(err)
	}
}
