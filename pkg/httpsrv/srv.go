package httpsrv

import (
	"context"
	"crypto/rsa"
	"fmt"
	"github.com/Dimss/centralsso/pkg/ui"
	limit "github.com/aviddiviner/gin-limit"
	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	upgrader = websocket.Upgrader{}
	bg       = ""
	title    = ""
)

func Run(addr, bgColor, t string) {
	go func() {

		bg = bgColor

		title = t

		r := gin.Default()

		r.Use(limit.MaxAllowed(1))

		r.StaticFS("/public", mustFS())

		r.GET("/", indexHandler)

		r.GET("/index.html", indexHandler)

		r.GET("/api/:ping", apiHandler)

		r.GET("/jwt", generateJWT)

		r.GET("/websocket", webSocketHandler)

		r.GET("/central.html", centralHandler)

		r.GET("/ready/:sleep", readyHandler)

		r.GET("/dex-login", dexLogin)

		r.GET("/dex-callback", dexCallback)

		if err := r.Run(addr); err != nil {
			log.Fatal(err)
		}
	}()
}

func oidcSetup() (*oidc.IDTokenVerifier, oauth2.Config) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, viper.GetString("dex-issuer-url"))
	x := viper.GetString("dex-redirect-url")

	fmt.Println(x)
	if err != nil {
		fmt.Println(err)
	}
	oauth2Config := oauth2.Config{
		// client_id and client_secret of the client.
		ClientID:     "example-app",
		ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV0",

		// The redirectURL.
		RedirectURL: viper.GetString("dex-redirect-url"),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		//
		// Other scopes, such as "groups" can be requested.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	return provider.Verifier(&oidc.Config{ClientID: "example-app"}), oauth2Config
}

func dexLogin(c *gin.Context) {
	_, oauth2Config := oidcSetup()
	c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL("foo-bar"))
}

func dexCallback(c *gin.Context) {
	var (
		err   error
		token *oauth2.Token
	)
	verifier, oauth2Config := oidcSetup()
	code := c.Request.FormValue("code")
	token, err = oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		fmt.Println(err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		fmt.Println(err)
		return
	}

	_, err = verifier.Verify(c.Request.Context(), rawIDToken)
	if err != nil {
		fmt.Println(err)
		return
	}

	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		fmt.Println(err)
		return
	}
	c.Request.Header.Add("raw-id-token", rawIDToken)
	c.Request.Header.Add("access-token", accessToken)

	provider, err := oidc.NewProvider(context.Background(), viper.GetString("dex-issuer-url"))

	if err != nil {
		fmt.Println(err)
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: "example-app"})
	verifiedIdToken, err := idTokenVerifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		fmt.Println(err)
	}

	c.Request.Header.Add("expiry-on-verified-id-token", verifiedIdToken.Expiry.String())

	c.Data(http.StatusOK, "text/html", ui.NewCentral(title, bg, c.Request.Header).Parse())

}

func centralHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/html", ui.NewCentral(title, bg, c.Request.Header).Parse())
}

func indexHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, viper.GetString("app-url"))
}

func readyHandler(c *gin.Context) {
	sleep, _ := strconv.ParseInt(c.Param("sleep"), 10, 64)
	time.Sleep(time.Duration(sleep) * time.Second)
	c.JSON(http.StatusOK, gin.H{"sleep": sleep})
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

func generateJWT(c *gin.Context) {
	signKey, err := getPrivateKey()
	if err != nil {
		log.Error(err)
		return
	}

	claims := jwt.MapClaims{
		"email":  c.Request.Header["X-Forwarded-Email"][0],
		"exp":    time.Now().UTC().Add(time.Hour * 24).Unix(),
		"iss":    viper.GetString("jwt-iis"),
		"aud":    "cnvrg-tenant",
		"groups": []string{viper.GetString("domain-id")},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(signKey)
	c.JSON(http.StatusOK, gin.H{
		"Token": tokenStr,
	})

}

func getPrivateKey() (*rsa.PrivateKey, error) {
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
