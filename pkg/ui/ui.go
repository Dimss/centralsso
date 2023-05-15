package ui

import (
	"bytes"
	"embed"
	"github.com/Masterminds/sprig"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"html/template"
	"io/fs"
)

//go:embed tmpl/assets*
var HtmlAssets embed.FS

//go:embed tmpl/index.html
var htmlIndex embed.FS

//go:embed tmpl/central.html
var htmlCentral embed.FS

type Central struct {
	Name    string
	Color   string
	Title   string
	Headers map[string][]string
}

type Index struct {
	Name   string
	AppUrl string
}

func NewIndex() *Index {
	return &Index{
		Name:   "index.html",
		AppUrl: viper.GetString("app-url"),
	}
}

func (i *Index) Parse() []byte {
	return parse(htmlIndex, i.Name, i)
}

func NewCentral(title, color string, h map[string][]string) *Central {
	return &Central{
		Name:    "central.html",
		Color:   color,
		Title:   title,
		Headers: h,
	}
}

func (c *Central) Parse() []byte {
	return parse(htmlCentral, c.Name, c)
}

func parse(fs fs.FS, templateName string, data interface{}) []byte {
	var tpl bytes.Buffer
	t, err := template.New(templateName).
		Option("missingkey=error").
		Funcs(sprig.HtmlFuncMap()).
		ParseFS(fs, "tmpl/"+templateName)

	if err != nil {
		log.Error(err)
		return nil
	}

	if err := t.ExecuteTemplate(&tpl, templateName, data); err != nil {
		log.Error(err)
	}
	return tpl.Bytes()
}
