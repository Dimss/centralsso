package srv

import (
	"crypto/rsa"
	"fmt"
	"github.com/AccessibleAI/centralsso/pkg/ui"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	upgrader = websocket.Upgrader{}
	bg       = ""
	title    = ""
)

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

	r.GET("/central.html", centralHandler)

	r.GET("/ready", readyHandler)

	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func centralHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/html", ui.NewCentral(title, bg, c.Request.Header).Parse())
}

func indexHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/html", ui.NewIndex().Parse())
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
