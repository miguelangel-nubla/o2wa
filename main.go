package main

import (
	_ "embed"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/miguelangel-nubla/o2wa/cmd/o2wa"
	"github.com/xeipuuv/gojsonschema"
)

//go:embed schema.json
var configSchema []byte

type Config struct {
	ClientID     string          `json:"clientID" yaml:"clientID"`
	ClientSecret string          `json:"clientSecret" yaml:"clientSecret"`
	OidcIssuer   string          `json:"oidcIssuer" yaml:"oidcIssuer"`
	CallbackURL  string          `json:"callbackURL" yaml:"callbackURL"`
	Endpoints    []o2wa.Endpoint `json:"endpoints" yaml:"endpoints"`
	TLSCert      string          `json:"tlsCert,omitempty" yaml:"tlsCert,omitempty"`
	TLSKey       string          `json:"tlsKey,omitempty" yaml:"tlsKey,omitempty"`
	ListenAddr   string          `json:"listenAddr" yaml:"listenAddr"`
}

func main() {
	// Load configuration from yaml
	config := loadConfig("config.yaml")

	app := o2wa.NewServer(config.ClientID, config.ClientSecret, config.OidcIssuer, config.CallbackURL)

	for _, endpoint := range config.Endpoints {
		http.HandleFunc(endpoint.Path, app.Handler(endpoint))
	}

	u, err := url.Parse(config.CallbackURL)
	if err != nil {
		log.Fatalf("Failed to parse callbackURL: %s", err)
	}

	http.HandleFunc("/values", app.AuthMiddleware([]string{}, app.EndpointValues))
	http.HandleFunc("/logout", app.EndpointLogout)
	http.HandleFunc(u.Path, app.Oauth2Callback)

	server := &http.Server{
		Addr:              config.ListenAddr,
		Handler:           app.SessionMiddleware(http.DefaultServeMux),
		ReadHeaderTimeout: 10 * time.Second, // no write timeout: command output streams as long as the command runs
	}

	if config.TLSCert != "" && config.TLSKey != "" {
		log.Printf("listening on https://%s/", config.ListenAddr)
		log.Fatal(server.ListenAndServeTLS(config.TLSCert, config.TLSKey))
	} else {
		log.Printf("listening on http://%s/", config.ListenAddr)
		log.Fatal(server.ListenAndServe())
	}
}

func loadConfig(filename string) Config {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open config file: %s", err)
	}
	defer file.Close()

	// Load the YAML content
	var config Config
	decoder := yaml.NewDecoder(file)
	// A misspelled key must fail the start: ignored, "requiredGroup" would leave an endpoint open to every login.
	decoder.KnownFields(true)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Failed to decode config file: %s", err)
	}

	// Convert the YAML config to JSON for validation using the schema
	jsonData, err := json.Marshal(config)
	if err != nil {
		log.Fatalf("Failed to convert YAML to JSON: %s", err)
	}

	// Load the schema and document
	schemaLoader := gojsonschema.NewBytesLoader(configSchema)
	documentLoader := gojsonschema.NewBytesLoader(jsonData) // use the converted JSON here

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		log.Fatalf("Failed to validate config: %s", err)
	}

	if !result.Valid() {
		for _, desc := range result.Errors() {
			// Print error description, for example
			log.Printf("- %s\n", desc)
		}
		log.Fatal("Config validation failed")
	}

	for _, endpoint := range config.Endpoints {
		if err := endpoint.Validate(); err != nil {
			log.Fatalf("Config validation failed: %s", err)
		}
	}
	if config.ListenAddr == "" {
		config.ListenAddr = ":8080"
	}
	return config
}
