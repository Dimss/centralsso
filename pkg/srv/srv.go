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
	c.Header("Authorization", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrMzJJQnkxb1lJZDVZcVdySVdGeWprMlVIVHhPbjRicC1CRFRCN3RrTEJFIn0.eyJleHAiOjE2NjUzMTQ4NDEsImlhdCI6MTY2NTMxNDU0MSwiYXV0aF90aW1lIjoxNjY1MzE0NTQxLCJqdGkiOiI4YWMzYzM4MC1jYWIyLTQ5NGEtOWE5OC0wZDgyOTY5OWIxNTEiLCJpc3MiOiJodHRwczovL2lkZW50aXR5LmRldi1jbG91ZC5jbnZyZy5pby9hdXRoL3JlYWxtcy9kaW1hLWxvYWQtdGVzdCIsImF1ZCI6Im15LXJlbGFtLTEiLCJzdWIiOiI2Nzk3YTg2My1kZmVhLTRlNjMtOWJlNy1mOTg3N2Q0YWYzZDAiLCJ0eXAiOiJJRCIsImF6cCI6Im15LXJlbGFtLTEiLCJzZXNzaW9uX3N0YXRlIjoiOWZkNjQ4NTEtYjExOS00MDA0LTljMmQtMjNjZTE4MDdhMDdhIiwiYXRfaGFzaCI6Im9oTVJYQndLZnltZkE4ZnpKZUYta3ciLCJhY3IiOiIxIiwic2lkIjoiOWZkNjQ4NTEtYjExOS00MDA0LTljMmQtMjNjZTE4MDdhMDdhIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJncm91cHMiOlsiL2Frcy1jaWNkLTExNTg5IiwiL2dyb3VwLTEiLCJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZXMtZGltYS1sb2FkLXRlc3QiLCJ1bWFfYXV0aG9yaXphdGlvbiJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJkaW1hQGNudnJnLmlvIiwiZW1haWwiOiJkaW1hQGNudnJnLmlvIn0.KOlm9fq-eIYviQSfM8bRcVDegycsegLJixGf70KjowWYKZbwOBV_BzKbS-HcIpFjQusHJy9twadl_FSTx-URASZDHwM3UmbEbD73NtfSmSf8jdtxiXJe-qE7sgeGXE60e86V6ZulevATQL9dz5d_6O5yHEaGLSYvk90yseiCDXRV4oxCk1oEANHXjJYO-QK2ej-nPsDJpCMfuGmje5t0dd10-KAKFGzoQF_1iUqhE1qkKVYO1jKxh3cYXA7qfFoOP1E6ZuMIBu78wZp3TXOlnJFRepJdPfRMuC2PbrgPVOuuA-qeNoIFB0htDAYNC0UtymDQQJ3BLhiyAGioN1_X4w\n")
	c.Data(http.StatusOK, "text/html", ui.NewIndex(title, bg, c.Request.Header).Parse())
}

func defaultIndexRedirectHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, "/index.html")
}

func apiHandler(c *gin.Context) {
	c.Header("X-CustomTestHeader", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJrMzJJQnkxb1lJZDVZcVdySVdGeWprMlVIVHhPbjRicC1CRFRCN3RrTEJFIn0.eyJleHAiOjE2NjUzMTQ4NDEsImlhdCI6MTY2NTMxNDU0MSwiYXV0aF90aW1lIjoxNjY1MzE0NTQxLCJqdGkiOiI4YWMzYzM4MC1jYWIyLTQ5NGEtOWE5OC0wZDgyOTY5OWIxNTEiLCJpc3MiOiJodHRwczovL2lkZW50aXR5LmRldi1jbG91ZC5jbnZyZy5pby9hdXRoL3JlYWxtcy9kaW1hLWxvYWQtdGVzdCIsImF1ZCI6Im15LXJlbGFtLTEiLCJzdWIiOiI2Nzk3YTg2My1kZmVhLTRlNjMtOWJlNy1mOTg3N2Q0YWYzZDAiLCJ0eXAiOiJJRCIsImF6cCI6Im15LXJlbGFtLTEiLCJzZXNzaW9uX3N0YXRlIjoiOWZkNjQ4NTEtYjExOS00MDA0LTljMmQtMjNjZTE4MDdhMDdhIiwiYXRfaGFzaCI6Im9oTVJYQndLZnltZkE4ZnpKZUYta3ciLCJhY3IiOiIxIiwic2lkIjoiOWZkNjQ4NTEtYjExOS00MDA0LTljMmQtMjNjZTE4MDdhMDdhIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJncm91cHMiOlsiL2Frcy1jaWNkLTExNTg5IiwiL2dyb3VwLTEiLCJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZXMtZGltYS1sb2FkLXRlc3QiLCJ1bWFfYXV0aG9yaXphdGlvbiJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJkaW1hQGNudnJnLmlvIiwiZW1haWwiOiJkaW1hQGNudnJnLmlvIn0.KOlm9fq-eIYviQSfM8bRcVDegycsegLJixGf70KjowWYKZbwOBV_BzKbS-HcIpFjQusHJy9twadl_FSTx-URASZDHwM3UmbEbD73NtfSmSf8jdtxiXJe-qE7sgeGXE60e86V6ZulevATQL9dz5d_6O5yHEaGLSYvk90yseiCDXRV4oxCk1oEANHXjJYO-QK2ej-nPsDJpCMfuGmje5t0dd10-KAKFGzoQF_1iUqhE1qkKVYO1jKxh3cYXA7qfFoOP1E6ZuMIBu78wZp3TXOlnJFRepJdPfRMuC2PbrgPVOuuA-qeNoIFB0htDAYNC0UtymDQQJ3BLhiyAGioN1_X4w\n")
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
