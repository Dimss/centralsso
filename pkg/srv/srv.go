package srv

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/AccessibleAI/centralsso/pkg/ui"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/websocket"
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	upgrader = websocket.Upgrader{}
	bg       = ""
	title    = ""
)

// initialize the code verifier
var CodeVerifier, _ = cv.CreateCodeVerifier()

func Run(addr, bgColor, t string) {

	bg = bgColor

	title = t

	r := gin.Default()

	r.StaticFS("/public", mustFS())

	r.GET("/api/:ping", apiHandler)

	r.GET("/jwt", generateJWT)

	r.GET("/websocket", webSocketHandler)

	r.GET("/", defaultIndexRedirectHandler)

	r.GET("/index.html", indexHandler)

	r.GET("/ready", readyHandler)

	r.GET("/start", oauth2StartHandler)

	r.GET("/client-creds", clientCreds)

	r.GET("/oauth2/callback", oauth2Callback)

	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func clientCreds(c *gin.Context) {
	ep := "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	params := url.Values{}
	params.Add("grant_type", "client_credentials")
	params.Add("client_id", "ed598141-b6e6-4a23-a135-4d5cdf1de980")
	//params.Add("client_secret", "GEa8Q~ACCtUZzOjCTZKF~FU9iOyFCQ1H1GOwTaYJ")
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("client_assertion", getJWT())
	params.Add("scope", "https://mvpcnvrg.onmicrosoft.com/api/.default")

	payload := strings.NewReader(params.Encode())

	req, _ := http.NewRequest("POST", ep, payload)

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("snap: HTTP error: %s", err)
		return
	}

	// process the response
	defer res.Body.Close()
	var responseData map[string]interface{}
	body, _ := io.ReadAll(res.Body)

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		fmt.Printf("snap: JSON error: %s", err)
		return
	}

	c.JSON(http.StatusOK, responseData)

}

func oauth2Callback(c *gin.Context) {
	code := c.Query("code")
	idToken := c.Query("id_token")
	log.Info(code)
	log.Info(idToken)
	ep := "https://mvpcnvrg.b2clogin.com/mvpcnvrg.onmicrosoft.com/b2c_1_test1/oauth2/v2.0/token"

	//scope := "https://mvpcnvrg.onmicrosoft.com/9134f43c-ea00-4a4e-b915-6bcc79483bd7/read openid offline_access email"
	scope := "7f98a8ec-0e21-44d2-ae27-af0c22a1bba4 openid offline_access email"

	params := url.Values{}

	params.Add("grant_type", "authorization_code")
	params.Add("client_id", "7f98a8ec-0e21-44d2-ae27-af0c22a1bba4")
	params.Add("scope", scope)
	params.Add("redirect_uri", "http://localhost:8080/oauth2/callback")
	params.Add("code", code)
	params.Add("client_secret", "PA48Q~d2ttb5CspEifK53F3GmE0aZOd1t7vyQaK4")
	//params.Add("code_verifier", CodeVerifier.String())

	payload := strings.NewReader(params.Encode())

	req, _ := http.NewRequest("POST", ep, payload)

	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("snap: HTTP error: %s", err)
		return
	}

	// process the response``
	defer res.Body.Close()
	var responseData map[string]interface{}
	body, _ := io.ReadAll(res.Body)

	// unmarshal the json into a string map
	err = json.Unmarshal(body, &responseData)
	if err != nil {
		fmt.Printf("snap: JSON error: %s", err)
		return
	}

	c.JSON(http.StatusOK, responseData)

}

func oauth2StartHandler(c *gin.Context) {
	authorizeEndpoint := "https://mvpcnvrg.b2clogin.com/mvpcnvrg.onmicrosoft.com/b2c_1_test1/oauth2/v2.0/authorize"
	req, err := http.NewRequest("GET", authorizeEndpoint, nil)
	if err != nil {
		log.Print(err)
		return
	}

	// Create code_challenge with S256 method
	//codeChallenge := CodeVerifier.CodeChallengeS256()

	//scope := "https://mvpcnvrg.onmicrosoft.com/9134f43c-ea00-4a4e-b915-6bcc79483bd7/read openid offline_access email"

	scope := "7f98a8ec-0e21-44d2-ae27-af0c22a1bba4 openid offline_access email"

	q := req.URL.Query()
	q.Add("client_id", "7f98a8ec-0e21-44d2-ae27-af0c22a1bba4")
	q.Add("response_type", "code")
	q.Add("redirect_uri", "http://localhost:8080/oauth2/callback")
	q.Add("response_mode", "query")
	q.Add("scope", scope)
	q.Add("state", "12345")
	//q.Add("code_challenge", codeChallenge)
	//q.Add("code_challenge_method", "S256")
	req.URL.RawQuery = q.Encode()

	c.Redirect(http.StatusFound, req.URL.String())
}

func indexHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/html", ui.NewIndex(title, bg, c.Request.Header).Parse())
}

func readyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}

func defaultIndexRedirectHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, "/index.html")
}

func apiHandler(c *gin.Context) {
	jsonRep := gin.H{
		c.Param("ping"): "pong",
		"time":          time.Now().Format(time.UnixDate),
	}

	for k, v := range c.Request.Header {
		jsonRep[k] = strings.Join(v, " ")
	}

	c.JSON(http.StatusOK, jsonRep)
}

func getx5t() string {

	pemContent, err := os.ReadFile("/Users/dkartsev/.go/src/github.com/AccessibleAI/centralsso/config/certs/user.crt")
	if err != nil {
		log.Error(err)
		return ""
	}

	block, _ := pem.Decode(pemContent)
	if block == nil {
		panic("Failed to parse pem file")
	}

	// pass cert bytes
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	fingerprint := sha1.Sum(cert.Raw)
	return b64.StdEncoding.EncodeToString(fingerprint[:])

}

func getJWT() string {
	signKey, err := getPrivateKey()
	if err != nil {
		log.Error(err)
		return ""
	}

	claims := jwt.MapClaims{
		"aud": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		"exp": time.Now().UTC().Add(time.Hour * 24).Unix(),
		"iss": "ed598141-b6e6-4a23-a135-4d5cdf1de980",
		"jti": "22b3bb26-e046-42df-9c96-65dbd72c1c81",
		"sub": "ed598141-b6e6-4a23-a135-4d5cdf1de980",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["x5t"] = getx5t()
	tokenStr, err := token.SignedString(signKey)
	if err != nil {
		log.Error(err)
	}
	//tokenStr = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dCI6ImNzWlJER3NvdVhwWnQrVXRCczIxVWNtWm9vTT0ifQ.eyJpc3MiOiJlZDU5ODE0MS1iNmU2LTRhMjMtYTEzNS00ZDVjZGYxZGU5ODAiLCJzdWIiOiJlZDU5ODE0MS1iNmU2LTRhMjMtYTEzNS00ZDVjZGYxZGU5ODAiLCJleHAiOjE2NzY5MTU3MTUsImp0aSI6IjIyYjNiYjI2LWUwNDYtNDJkZi05Yzk2LTY1ZGJkNzJjMWM4MSIsImF1ZCI6Imh0dHBzOi8vbG9naW4ubWljcm9zb2Z0b25saW5lLmNvbS9jb21tb24vb2F1dGgyL3YyLjAvdG9rZW4ifQ.HnufUeztGFRKcP3WbmuuzI3YWvBEzm4lVwgt5Q4NOQv0LW19L2O6MJE8PGxvVMdj52muoqinQDaRiW84dQClQCyC7zMhi6yBVlA0urQvn1npwl39Xh5X2H2DZEpaJ5TGbzOZ36-_h2BGAD5HHjUOUxaEgVZmbH5pa-QL9mHN0YH0rPc-joasadPbcZWKJYIlpor6V1Hh76vaQIBt7TFId4G79HBG4JgvxiUdud_idrC4N3yexpM1WhHHCMKHfpy_a58PonMJujeAorO1ZtPoTJXd4QiNuFZqap7EQM8knE7vH8ARLZ_L9RwA6MvJX6mhAaEcrkFfHxZgeIH4bfuJDA"
	return tokenStr

}

func generateJWT(c *gin.Context) {
	signKey, err := getPrivateKey()
	if err != nil {
		log.Error(err)
		return
	}

	//email := "unknown@unknown.unknown"
	//if len(c.Request.Header["X-Forwarded-Email"]) > 0 {
	//	email = c.Request.Header["X-Forwarded-Email"][0]
	//}
	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"aud": "cnvrg-tenant",
		"exp": time.Now().UTC().Add(time.Hour * 24).Unix(),
		"iss": "ed598141-b6e6-4a23-a135-4d5cdf1de980",
		"jti": "foo-bar",
		"iat": now,
		"nbf": now,
		"sub": "ed598141-b6e6-4a23-a135-4d5cdf1de980",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(signKey)
	c.JSON(http.StatusOK, gin.H{
		"Token": tokenStr,
	})

}

func getPrivateKey() (*rsa.PrivateKey, error) {
	log.Info(viper.GetString("sign-key"))
	privateKey, err := os.ReadFile(viper.GetString("sign-key"))
	if err != nil {
		return nil, err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return signKey, nil
}

func webSocketHandler(c *gin.Context) {
	ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer ws.Close()
	for {
		//Read Message from client
		mt, message, err := ws.ReadMessage()
		if err != nil {
			fmt.Println(err)
			break
		}
		//If client message is ping will return pong
		if string(message) == "ping" {
			message = []byte(fmt.Sprintf("[%s] pong", time.Now().Format(time.UnixDate)))
		}
		//Response message to client
		err = ws.WriteMessage(mt, message)
		if err != nil {
			fmt.Println(err)
			break
		}
	}
	defer ws.Close()
}

func mustFS() http.FileSystem {
	sub, err := fs.Sub(ui.HtmlAssets, "tmpl/assets")

	if err != nil {
		panic(err)
	}

	return http.FS(sub)
}
