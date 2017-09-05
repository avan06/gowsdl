// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package gowsdl

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode"
)

const maxRecursion uint8 = 20

// GoWSDL defines the struct for WSDL generator.
type GoWSDL struct {
	file, pkg             string
	ignoreTLS             bool
	makePublicFn          func(string) string
	wsdl                  *WSDL
	resolvedXSDExternals  map[string]bool
	currentRecursionLevel uint8
	usageTypeName         bool
}

var cacheDir = filepath.Join(os.TempDir(), "gowsdl-cache")

func init() {
	err := os.MkdirAll(cacheDir, 0700)
	if err != nil {
		log.Println("Create cache directory", "error", err)
		os.Exit(1)
	}
}

var timeout = time.Duration(30 * time.Second)

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

func downloadFile(url string, ignoreTLS bool) ([]byte, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: ignoreTLS,
		},
		Dial: dialTimeout,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Received response code %d", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// NewGoWSDL initializes WSDL generator.
func NewGoWSDL(file, pkg string, ignoreTLS bool, exportAllTypes bool, usageTypeName bool) (*GoWSDL, error) {
	file = strings.TrimSpace(file)
	if file == "" {
		return nil, errors.New("WSDL file is required to generate Go proxy")
	}

	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		pkg = "myservice"
	}
	makePublicFn := func(id string) string { return id }
	if exportAllTypes {
		makePublicFn = makePublic
	}

	return &GoWSDL{
		file:          file,
		pkg:           pkg,
		ignoreTLS:     ignoreTLS,
		makePublicFn:  makePublicFn,
		usageTypeName: usageTypeName,
	}, nil
}

// Start initiaties the code generation process by starting two goroutines: one
// to generate types and another one to generate operations.
func (g *GoWSDL) Start() (map[string][]byte, error) {
	gocode := make(map[string][]byte)

	err := g.unmarshal()
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error

		gocode["types"], err = g.genTypes()
		if err != nil {
			log.Println("genTypes", "error", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error

		gocode["operations"], err = g.genOperations()
		if err != nil {
			log.Println(err)
		}
	}()

	wg.Wait()

	gocode["header"], err = g.genHeader()
	if err != nil {
		log.Println(err)
	}

	gocode["soap"], err = g.genSOAPClient()
	if err != nil {
		log.Println(err)
	}

	return gocode, nil
}

func (g *GoWSDL) unmarshal() error {
	var data []byte

	parsedURL, err := url.Parse(g.file)
	if isHttp, _ := regexp.MatchString("^[hH][tT][tT][pP].*", parsedURL.Scheme); isHttp {
		log.Println("Downloading", "file", g.file)

		data, err = downloadFile(g.file, g.ignoreTLS)
		if err != nil {
			return err
		}
	} else {
		log.Printf("ReadFile location %s", g.file)

		data, err = ioutil.ReadFile(g.file)
		if err != nil {
			return err
		}
	}

	g.wsdl = new(WSDL)
	err = xml.Unmarshal(data, g.wsdl)
	if err != nil {
		return err
	}

	for _, wsdlImport := range g.wsdl.Imports {
		download(g, parsedURL, wsdlImport.Location, "wsdl")
	}

	for _, schema := range g.wsdl.Types.Schemas {
		err = g.resolveXSDExternals(schema, parsedURL)
		if err != nil {
			return err
		}
	}

	if !g.usageTypeName {
		for _, schema := range g.wsdl.Types.Schemas {
			for _, complexType := range schema.ComplexTypes {
				for _, element := range complexType.Sequence {
					elementTypeChk(schema, &element, false)
				}
			}

			for _, element := range schema.Elements {
				elementTypeChk(schema, element, true)
			}
		}
	}

	return nil
}

func elementTypeChk(schema *XSDSchema, element *XSDElement, isAddSimple bool) {
	if element.ComplexType != nil && len(element.ComplexType.Sequence) > 0 {
		for _, element := range element.ComplexType.Sequence {
			elementTypeChk(schema, &element, false)
		}
	}
	if element.Type != "" {
		if xsd2GoTypes[strings.ToLower(removeNS(element.Type))] != "" {
			if isAddSimple {
				if simpleType := findSimpleType(schema.SimpleType, element.Name); simpleType == nil {
					simpleType := &XSDSimpleType{Name: element.Name, Restriction: XSDRestriction{Base: element.Type}}
					schema.SimpleType = append(schema.SimpleType, simpleType)
				}
			}
		} else if simpleType := findSimpleType(schema.SimpleType, element.Type); simpleType != nil {
			element.SimpleType = simpleType
			element.Type = ""
		}

		if complexType := findComplexType(schema.ComplexTypes, element.Type); complexType != nil {
			element.ComplexType = complexType
			element.Type = ""
		}
	}
}

func findSimpleType(simpleTypes []*XSDSimpleType, typeName string) *XSDSimpleType {
	for _, simpleType := range simpleTypes {
		if simpleType.Name == removeNS(typeName) {
			return simpleType
		}
	}

	return nil
}

func findComplexType(complexTypes []*XSDComplexType, typeName string) *XSDComplexType {
	for _, complexType := range complexTypes {
		if complexType.Name == removeNS(typeName) {
			return complexType
		}
	}

	return nil
}

func (g *GoWSDL) resolveXSDExternals(schema *XSDSchema, u *url.URL) error {
	for _, impts := range schema.Imports {
		if e := download(g, u, impts.SchemaLocation, ""); e != nil {
			return e
		}
	}

	for _, incl := range schema.Includes {
		if e := download(g, u, schema.TargetNamespace+"/"+incl.SchemaLocation, ""); e != nil {
			return e
		}
	}
	return nil

}

func download(g *GoWSDL, u1 *url.URL, loc string, schemaType string) error {
	var data []byte
	var locationDir, locationName string
	location, err := u1.Parse(loc)
	if err != nil {
		return err
	}

	if location.Host == "" && location.Path != "" {
		locationDir, locationName = filepath.Split(location.Path)
	} else {
		locationDir, locationName = filepath.Split(location.String())
	}

	if g.resolvedXSDExternals[locationName] {
		return nil
	}

	if isHttp, _ := regexp.MatchString("^[hH][tT][tT][pP].*", location.Scheme); isHttp {
		schemaLocation := location.String()
		if !u1.IsAbs() {
			return fmt.Errorf("Unable to resolve external schema %s through WSDL URL %s", schemaLocation, u1)
		}
		//schemaLocation = u1.Scheme + "://" + u1.Host + schemaLocation

		log.Println("Downloading external schema", "location", schemaLocation)

		if data, err = downloadFile(schemaLocation, g.ignoreTLS); err != nil {
			return err
		}
	} else {
		if isRelative, _ := regexp.MatchString(`^[/\\]{0,1}\.{0,1}[/\\]$`, locationDir); isRelative {
			locationDir, _ = filepath.Split(u1.String())
		}
		log.Printf("ReadFile location %s%s", locationDir, locationName)
		if data, err = ioutil.ReadFile(locationDir + locationName); err != nil {
			return err
		}
	}

	if schemaType == "wsdl" {
		newSchema := new(WSDL)

		err = xml.Unmarshal(data, newSchema)
		if err != nil {
			return err
		}
		if len(newSchema.Types.Schemas) > 0 {
			g.wsdl.Types = newSchema.Types
		}
		if len(newSchema.Messages) > 0 {
			g.wsdl.Messages = newSchema.Messages
		}
		if len(newSchema.PortTypes) > 0 {
			g.wsdl.PortTypes = newSchema.PortTypes
		}
		if len(newSchema.Binding) > 0 {
			g.wsdl.Binding = newSchema.Binding
		}
		if len(newSchema.Service) > 0 {
			g.wsdl.Service = newSchema.Service
		}
	} else {
		newSchema := new(XSDSchema)

		err = xml.Unmarshal(data, newSchema)
		if err != nil {
			return err
		}

		if len(newSchema.Includes) > 0 &&
			maxRecursion > g.currentRecursionLevel {
			g.currentRecursionLevel++

			// log.Printf("Entering recursion %d\n", g.currentRecursionLevel)
			err = g.resolveXSDExternals(newSchema, u1)
			if err != nil {
				return err
			}
		}

		g.wsdl.Types.Schemas = append(g.wsdl.Types.Schemas, newSchema)
	}

	if g.resolvedXSDExternals == nil {
		g.resolvedXSDExternals = make(map[string]bool, maxRecursion)
	}
	g.resolvedXSDExternals[locationName] = true

	return nil

}

func (g *GoWSDL) genTypes() ([]byte, error) {
	funcMap := template.FuncMap{
		"toGoType":             toGoType,
		"stripns":              stripns,
		"replaceReservedWords": replaceReservedWords,
		"makePublic":           g.makePublicFn,
		"makeFieldPublic":      makePublic,
		"comment":              comment,
		"removeNS":             removeNS,
		"goString":             goString,
	}

	//TODO resolve element refs in place.
	//g.resolveElementsRefs()

	data := new(bytes.Buffer)
	tmpl := template.Must(template.New("types").Funcs(funcMap).Parse(typesTmpl))
	err := tmpl.Execute(data, g.wsdl.Types)
	if err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

func (g *GoWSDL) genOperations() ([]byte, error) {
	funcMap := template.FuncMap{
		"toGoType":             toGoType,
		"stripns":              stripns,
		"replaceReservedWords": replaceReservedWords,
		"makePublic":           g.makePublicFn,
		"findType":             g.findType,
		"findSOAPAction":       g.findSOAPAction,
		"findServiceAddress":   g.findServiceAddress,
	}

	data := new(bytes.Buffer)
	tmpl := template.Must(template.New("operations").Funcs(funcMap).Parse(opsTmpl))
	err := tmpl.Execute(data, g.wsdl.PortTypes)
	if err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

func (g *GoWSDL) genHeader() ([]byte, error) {
	funcMap := template.FuncMap{
		"toGoType":             toGoType,
		"stripns":              stripns,
		"replaceReservedWords": replaceReservedWords,
		"makePublic":           g.makePublicFn,
		"findType":             g.findType,
		"comment":              comment,
	}

	data := new(bytes.Buffer)
	tmpl := template.Must(template.New("header").Funcs(funcMap).Parse(headerTmpl))
	err := tmpl.Execute(data, g.pkg)
	if err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

func (g *GoWSDL) genSOAPClient() ([]byte, error) {
	data := new(bytes.Buffer)
	tmpl := template.Must(template.New("soapclient").Parse(soapTmpl))
	err := tmpl.Execute(data, g.pkg)
	if err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}

var reservedWords = map[string]string{
	"break":       "break_",
	"default":     "default_",
	"func":        "func_",
	"interface":   "interface_",
	"select":      "select_",
	"case":        "case_",
	"defer":       "defer_",
	"go":          "go_",
	"map":         "map_",
	"struct":      "struct_",
	"chan":        "chan_",
	"else":        "else_",
	"goto":        "goto_",
	"package":     "package_",
	"switch":      "switch_",
	"const":       "const_",
	"fallthrough": "fallthrough_",
	"if":          "if_",
	"range":       "range_",
	"type":        "type_",
	"continue":    "continue_",
	"for":         "for_",
	"import":      "import_",
	"return":      "return_",
	"var":         "var_",
}

// Replaces Go reserved keywords to avoid compilation issues
func replaceReservedWords(identifier string) string {
	value := reservedWords[identifier]
	if value != "" {
		return value
	}
	return normalize(identifier)
}

// Normalizes value to be used as a valid Go identifier, avoiding compilation issues
func normalize(value string) string {
	mapping := func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			return r
		}
		return -1
	}

	return strings.Map(mapping, value)
}

func goString(s string) string {
	return strings.Replace(s, "\"", "\\\"", -1)
}

var xsd2GoTypes = map[string]string{
	"string":        "string",
	"token":         "string",
	"float":         "float32",
	"double":        "float64",
	"decimal":       "float64",
	"integer":       "int32",
	"int":           "int32",
	"short":         "int16",
	"byte":          "int8",
	"long":          "int64",
	"boolean":       "bool",
	"datetime":      "time.Time",
	"date":          "time.Time",
	"time":          "time.Time",
	"base64binary":  "[]byte",
	"hexbinary":     "[]byte",
	"unsignedint":   "uint32",
	"unsignedshort": "uint16",
	"unsignedbyte":  "byte",
	"unsignedlong":  "uint64",
	"anytype":       "interface{}",
}

func removeNS(xsdType string) string {
	// Handles name space, ie. xsd:string, xs:string
	r := strings.Split(xsdType, ":")

	if len(r) == 2 {
		return r[1]
	} else {
		return r[0]
	}
}

func toGoType(xsdType string) string {
	// Handles name space, ie. xsd:string, xs:string
	r := strings.Split(xsdType, ":")

	t := r[0]

	if len(r) == 2 {
		t = r[1]
	}

	value := xsd2GoTypes[strings.ToLower(t)]

	if value != "" {
		return value
	}

	return "*" + replaceReservedWords(makePublic(t))
}

// Given a message, finds its type.
//
// I'm not very proud of this function but
// it works for now and performance doesn't
// seem critical at this point
func (g *GoWSDL) findType(message string) string {
	message = stripns(message)

	for _, msg := range g.wsdl.Messages {
		if msg.Name != message {
			continue
		}

		// Assumes document/literal wrapped WS-I
		if len(msg.Parts) == 0 {
			// Message does not have parts. This could be a Port
			// with HTTP binding or SOAP 1.2 binding, which are not currently
			// supported.
			log.Printf("[WARN] %s message doesn't have any parts, ignoring message...", msg.Name)
			continue
		}

		part := msg.Parts[0]
		if g.usageTypeName && part.Type != "" {
			return stripns(part.Type)
		}

		elRef := stripns(part.Element)

		for _, schema := range g.wsdl.Types.Schemas {
			for _, el := range schema.Elements {
				if strings.EqualFold(elRef, el.Name) {
					if g.usageTypeName && el.Type != "" {
						return stripns(el.Type)
					}
					return el.Name
				}
			}
		}
	}
	return ""
}

// TODO(c4milo): Add support for namespaces instead of striping them out
// TODO(c4milo): improve runtime complexity if performance turns out to be an issue.
func (g *GoWSDL) findSOAPAction(operation, portType string) string {
	for _, binding := range g.wsdl.Binding {
		if stripns(binding.Type) != portType {
			continue
		}

		for _, soapOp := range binding.Operations {
			if soapOp.Name == operation {
				return soapOp.SOAPOperation.SOAPAction
			}
		}
	}
	return ""
}

func (g *GoWSDL) findServiceAddress(name string) string {
	for _, service := range g.wsdl.Service {
		for _, port := range service.Ports {
			if port.Name == name {
				return port.SOAPAddress.Location
			}
		}
	}
	return ""
}

// TODO(c4milo): Add namespace support instead of stripping it
func stripns(xsdType string) string {
	r := strings.Split(xsdType, ":")
	t := r[0]

	if len(r) == 2 {
		t = r[1]
	}

	return t
}

func makePublic(identifier string) string {
	field := []rune(identifier)
	if len(field) == 0 {
		return identifier
	}

	field[0] = unicode.ToUpper(field[0])
	return string(field)
}

func comment(text string) string {
	lines := strings.Split(text, "\n")

	var output string
	if len(lines) == 1 && lines[0] == "" {
		return ""
	}

	// Helps to determine if there is an actual comment without screwing newlines
	// in real comments.
	hasComment := false

	for _, line := range lines {
		line = strings.TrimLeftFunc(line, unicode.IsSpace)
		if line != "" {
			hasComment = true
		}
		output += "\n// " + line
	}

	if hasComment {
		return output
	}
	return ""
}
