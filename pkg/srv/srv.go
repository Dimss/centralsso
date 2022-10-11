package srv

import (
	"fmt"
	"github.com/AccessibleAI/centralsso/pkg/ui"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"io/fs"
	"net/http"
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

	r.GET("/websocket", webSocketHandler)

	r.GET("/", defaultIndexRedirectHandler)

	r.GET("/index.html", indexHandler)

	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func indexHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/html", ui.NewIndex(title, bg, c.Request.Header).Parse())
}

func defaultIndexRedirectHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, "/index.html")
}

func apiHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		c.Param("ping"): "pong",
		"time":          time.Now().Format(time.UnixDate),
	})
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
