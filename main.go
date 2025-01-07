package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
)

const powLength = 1
const prefixLength = 8

var clients = map[uuid.UUID][][powLength + prefixLength]byte{}

func main() {
	port := flag.String("port", "8080", "port to listen on")
	target := flag.String("url", "http://127.0.0.1:80", "target server")

	flag.Parse()

	targetURL, err := url.Parse(*target)
	if err != nil {
		log.Fatal(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Check for the powroxy-user uidCookie
		uidCookie, err := r.Cookie("_powroxyuid")
		var userChallenges [][powLength + prefixLength]byte
		var parseErr error
		var parsedPowUid uuid.UUID
		exists := false
		if err == nil {
			parsedPowUid, parseErr = uuid.Parse(uidCookie.Value)
		}
		if err == nil && parseErr == nil {
			userChallenges, exists = clients[parsedPowUid]
		}
		if err != nil || !exists {
			// If the cookie doesn't exist, create a new one
			uid := uuid.New()
			uidCookie = &http.Cookie{
				Name:  "_powroxyuid",
				Value: uid.String(),
			}
			http.SetCookie(w, uidCookie)
			clients[uid] = [][powLength + prefixLength]byte{}
		}

		// Check if the POW matches an issued challenge
		powCookie, err := r.Cookie("_powroxy")
		parsedPowSolve := ""
		if err == nil {
			parsedPowSolve = powCookie.Value
		}
		if len(parsedPowSolve) >= prefixLength {
			powHash := sha256.Sum256([]byte(parsedPowSolve))
			//fmt.Printf("Checking POW: %s : %x\n", parsedPowSolve, powHash)
			for _, challenge := range userChallenges {
				matches := true
				for i := 0; i < powLength; i++ {
					if powHash[i] != challenge[i] {
						matches = false
						//fmt.Println("Failed hash check: ", powHash[i], challenge[i])
						break
					}
				}
				if matches {
					prefixHex := fmt.Sprintf("%x", challenge[powLength:])
					for i := 0; i < prefixLength; i++ {
						if parsedPowSolve[i] != prefixHex[i] {
							matches = false
							//fmt.Println("Failed prefix check: ", parsedPowSolve[i], prefixHex[i])
							break
						}
					}
				}
				if matches {
					// If the POW matches, remove the challenge and continue
					newChallenges := [][powLength + prefixLength]byte{}
					for _, c := range userChallenges {
						if c != challenge {
							newChallenges = append(newChallenges, c)
						}
					}
					//fmt.Println("Pow matched, removing challenge")
					clients[parsedPowUid] = newChallenges
					r.Host = targetURL.Host
					proxy.ServeHTTP(w, r)
					return
				}
			}
		}

		// If the cookie doesn't exist, return a POW challengePow that the client must solve with javascript
		challengePow := [powLength + prefixLength]byte{}
		for i := 0; i < powLength+prefixLength; i++ {
			challengePow[i] = byte(rand.Intn(256))
		}

		clients[parsedPowUid] = append(clients[parsedPowUid], challengePow)

		// Return a javascript body that solves the POW and then reloads
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<script>
async function sha256(message) {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
}

const challenge = "%x";
const prefix = "%x";

(async function proofOfWork() {
  while (true) {
    const attempt = prefix + Math.random().toString(16).substring(2);
    const hash = await sha256(attempt);

    if (hash.startsWith(challenge)) {
      document.cookie = '_powroxy='+attempt + '; path=/';
      location.reload();
      break;
    }
  }
})();
</script>
`, challengePow[:powLength], challengePow[powLength:])

	})

	fmt.Printf("Listening on :8080, forwarding to %s\n", targetURL)
	log.Fatal(http.ListenAndServe(":"+*port, nil))
}
