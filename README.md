
# RUXY

## A reverse proxy written in rust

Ruxy is an HTTP transparent reverse proxy that can be useful for inspecting or checking application behavior. Ruxy is developed mainly for microservice environments but its use is not strictly limited to those.

Features include (or will include):

- **request and response header logging**
- **request payload logging**
- **SSL adding/stripping**
- **http version translation** (\*)
- **canary releases**: put ruxy in front of two releases of the same application and use it to split traffic among them (\*)
- **extensible**: plan is to support a scripting language (maybe [lua](https://www.lua.org/)) to add your own behavior to ruxy (\*)

**Note**: This aplication is still under development and features marked with a (\*) are still not available

### Running

Ruxy can be built locally with:

	cargo build --release

and run by just launching it:

	./target/release/ruxy

On startup, ruxy will look for a `config.toml` file in the current directory and for some environment variables (see below for details) for its configuration. To use a different configuration file, provide its reference in the command line: `./ruxy -f /etc/ruxy.toml`

Ruxy can also be built as a docker image:

	docker build -t ruxy:latest .

### Configuration

Ruxy configuration file contains a main section where all the default behaviors are defined, and a `[filter]` section where you can define configuration overrides for specific HTTP requests.

Main section values can be also specified as environment variables.

This documentation, like the application itself, is still under development and for now you won't get all the details here, but the two values you always need to specify are **bind** and **remote** which are, respectively, the bind address for the listening socket and the url of the proxied application.

Exceptions to the default configurations are specified via *rules*, *actions* and *filters*.
Actions represent behavior flags for a single request, while filters are used to match a request. Rules are made of composition of filters and actions.

### Configuration samples

Minimal configuration:

	bind = "localhost:8080"
	remote = "https://www.alessandropira.org/"

SSL adding:

	bind = "0.0.0.0:443"
	remote = "http://localhost:8080/"

	server_ssl_trust = "./cert.pem"
	server_ssl_key = "./key.pem"

Log request payload for POSTs on a specific path and all headers on every request:

	bind = "localhost:8080"
	remote = "http://some-service-with-saml-auth/"
	log_headers = true

	[filters]
	post_on_saml = { path = "^/Shibboleth.sso/SAML/POST$", method = "POST" }

	[actions]
	log_payload = { log_request_body = true }

	[rules]
	r1 = { filters = [ "post_on_saml" ], actions = [ "log_payload" ] }

Redirect traffic having a specific header to a different endpoint:

	bind = "localhost:8080"
	remote = "http://public-server/"
	log_headers = true

	[filters]
	has_api_key = { headers = { X-Api-Key = "^SOME-SECRET$" } }

	[actions]
	redirect = { remote = "http://private-server/" }

	[rules]
	r1 = { filters = [ "has_api_key" ], actions = [ "redirect" ] }


