package ui

import (
	"bytes"
	"embed"
	"github.com/Masterminds/sprig"
	log "github.com/sirupsen/logrus"
	"html/template"
)

//go:embed tmpl/assets*
var HtmlAssets embed.FS

//go:embed tmpl/index.html
var htmlIndex embed.FS

type Index struct {
	Name    string
	Headers map[string][]string
}

func NewIndex(h map[string][]string) *Index {
	return &Index{
		Name:    "index.html",
		Headers: h,
	}
}

func (i *Index) Parse() []byte {
	var tpl bytes.Buffer
	t, err := template.New(i.Name).
		Option("missingkey=error").
		Funcs(sprig.HtmlFuncMap()).
		ParseFS(htmlIndex, "tmpl/"+i.Name)

	if err != nil {
		log.Error(err)
		return nil
	}

	if err := t.ExecuteTemplate(&tpl, i.Name, i); err != nil {
		log.Error(err)
	}
	return tpl.Bytes()

}
