package backend

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/tdewolff/minify"
	minicss "github.com/tdewolff/minify/css"
	minihtml "github.com/tdewolff/minify/html"
	minijs "github.com/tdewolff/minify/js"
	minijson "github.com/tdewolff/minify/json"
	minisvg "github.com/tdewolff/minify/svg"
	minixml "github.com/tdewolff/minify/xml"
)

type fileHandler struct {
	root         http.FileSystem
	innerHandler http.Handler
}

func MinifiedFileServer(root http.FileSystem) http.Handler {
	return &fileHandler{
		root:         root,
		innerHandler: http.FileServer(root),
	}
}

func (f *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upath := r.URL.Path
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}

	m := minify.New()
	m.AddFunc("text/css", minicss.Minify)
	m.AddFunc("text/html", minihtml.Minify)
	m.AddFunc("image/svg+xml", minisvg.Minify)
	m.AddFuncRegexp(regexp.MustCompile("^(application|text)/(x-)?(java|ecma)script$"), minijs.Minify)
	m.AddFuncRegexp(regexp.MustCompile("[/+]json$"), minijson.Minify)
	m.AddFuncRegexp(regexp.MustCompile("[/+]xml$"), minixml.Minify)

	mw := m.ResponseWriter(w, r)
	defer mw.Close()
	w = mw
	f.innerHandler.ServeHTTP(w, r)

}
