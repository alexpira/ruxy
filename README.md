
# RUXY

## A reverse proxy written in rust

Ruxy is an HTTP transparent reverse proxy that can be useful for inspecting or checking application behavior. Ruxy is developed mainly for microservice environments but its use is not strictly limited to those.

Features include (or will include):

- **request and response headers/payload logging**
- **TLS adding/stripping**
- **request and response header injection or removal**
- **http version translation**
- **canary releases**: put ruxy in front of two releases of the same application and use it to split traffic among them
- **extensible**: plan is to support a scripting language (maybe [lua](https://www.lua.org/)) to add your own behavior to ruxy (\*)

**Note**: This application is still under development and features marked with a (\*) are still not available

### Building

Ruxy is developed with [rust](https://www.rust-lang.org/) so in order to build ruxy you first need to have rust installed. Then, ruxy can be built by running:

	cargo build --release

and run by just launching it:

	./target/release/ruxy

On startup, ruxy will look for a `config.toml` file in the current directory and for some environment variables (see below for details) for its configuration. To use a different configuration file, provide its reference in the command line, i.e. `./ruxy -f /etc/ruxy.toml`

Ruxy can also be built as a docker image:

	docker build -t ruxy:latest .

### Configuration via environment

The full configuration toml content can be set to a single environment variable by running `./ruxy -e [ENV_NAME]`. That can be useful in k8s/docker environments as it simplifies deployment configuration.
Also, some global configurations can be specified via the following environment variables:

- **BIND**: the bind address and port for the listening socket (i.e. 127.0.0.1:8080)
- **REMOTE**: default remote url to send requests
- **REWRITE_HOST**: set to *true* to rewrite `Host` HTTP header according to remote url

That allows a minimal setup to be done very easily without a configuration file (i.e. `BIND=0.0.0.0:8080 REMOTE=https://www.alessandropira.org/ REWRITE_HOST=true ./ruxy`).

### Configuration

Ruxy configuration file contains a main section where all the default behaviors are defined, and subsections where you can define configuration overrides for specific HTTP requests.

This documentation, like the application itself, is still under development and for now you won't get all the details here, but the two values you always need to specify in the main part are **bind** and **remote** which are, respectively, the bind address for the listening socket and the url of the proxied application.

Exceptions to the default configurations are specified via *rules*, *actions* and *filters*.
Actions represent behavior flags for a single request, while filters are used to match a request. Rules are made of composition of filters and actions.

### Configuration samples

Minimal configuration:

	bind = "localhost:8080"
	remote = "https://www.alessandropira.org/"

TLS adding:

	bind = "0.0.0.0:443"
	remote = "http://localhost:8080/"

	server_ssl_cert = "./cert.pem"
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

Add an API key, replacing the header eventually received from the client, before forwarding the request to the remote server

	bind = "localhost:8080"
	remote = "http://some-service/"

	[filters]
	apis = { path = "^/api/" }

	[actions]
	add_api_key = { remove_request_headers = [ "X-Api-Key" ], add_request_headers = { X-Api-Key = "some_secret" } }

	[rules]
	r1 = { filters = [ "apis" ], actions = [ "add_api_key" ] }

Add twice the same header to a request

	bind = "localhost:8080"
	remote = "http://some-service/"

	add_request_headers = [ { header = "X-Double-Header", value = "first" }, { header = "X-Double-Header", value = "second" } ]


#### Main section parameters

Main section is used for generic parameters. Every parameter that can be defined for an action (see below "actions section") can also be present in the main section and will cotribute to define the default behavior of ruxy.

- **bind**: address and port for the listening socket, i.e.: `127.0.0.1:8080`
- **server_ssl_cert** and **server_ssl_key**: certificate and private key file for enabling TLS on listening socket
- **graceful_shutdown_timeout**: ruxy after receiving INT or TERM signals waits for this timeout to allow graceful termination of existing connections before shutting down; it must be specified as a string containing a number and one of the suffixes `"min"`, `"sec"` or `"ms"`; i.e.: `10sec` or `200ms`
- **log_stream**: boolean, enables low level log of all *server side* sent and received data (inside TLS), very verbose and useful for debugging of ruxy itself
- **http_server_version**: either "h1" (default) or "h2"; used to define HTTP version used on listening socket

Also, the following values can be defined in the main section to define the default behavior of ruxy: **remote** (mandatory), **rewrite_host**, **http_client_version**, **ssl_mode**, **cafile**, **log**, **log_level**, **log_headers**, **log_request_body**, **max_request_log_size**, **log_reply_body**, **max_reply_log_size**, **lua_request_script**, **lua_request_load_body**. See *actions* section for details.

#### Rules section

Rules are used to define overrides and are checked for every incoming request.

Inside rules section you can define values which can be described as json. Every rule can have a list of filters and a list of actions.

For every icoming HTTP request ruxy does the following:

- it checks every rule in the configuration
- for every rule, if there are filters defined, all the filters must match the incoming request, otherwise the rule is discarded
- the first matching rule is picked (rules are checked in alphabetical order)
- all the actions in the picked rule are applied for that specific request

The following attributes can be specified for a rule:

- **filters**: (array of strings) names of the filters associated with the rule
- **filter**: (string) single filter to be associated to the rule
- **actions**: (array of strings) names of the actions associated with the rule
- **action**: (string) single action to be associated to the rule
- **enabled**: (boolean) setting this to false makes ruxy ignore this rule; this is mostly useful as a runtime property but it can also be set in the configuration file
- **probability**: (float) when set, it indicates the chance that a rule will be used or ignored for a specific request; it should be set to a value between 0 and 1, i.e. if set to 0.25, the rule will be applied on an average of one request every four
- **disable_on**: (string) regex to match to the status code of the reply, if matched on a reply, the rule will be disabled and ignored for following requests; i.e. "5..", "[4-5].\*" are reasonable values 
- **keep_while**: (string) regex to match to the status code of the reply, if *not* matched on a reply, the rule will be disabled and ignored for following requests; i.e. "20[01]", "[2-3].." are reasonable values
- **max_life**: (integer) if set, the rule will be applied to at most this number of requests, and then will be disabled

Note: a rule without filters will be applied to all requests.

#### Filters section

Filters are used to match HTTP requests in order to select the rule to apply to a request.

- **method**: (string) regex to match the HTTP verb, i.e. "GET", "(HEAD)|(GET)"
- **path**: (string) regex to match the requested path (excluding query string)
- **headers**: (list of key-values) name of headers and relative regex to match the value

#### Actions section

Actions associated to the selected rule will be applied to the HTTP request before forwarding it and can be used to override the values defined in the main section.

All action properties can be specified in the main section to define default ruxy behavior.

- **remote**: (string) the remote url to forward requests to; this is a mandatory property in the main section
- **rewrite_host**: (boolean) if set to *true* ruxy will rewrite the "Host" request header (":authority:" for HTTPv2) to match the remote url value; the default is *false*
- **http_client_version**: (string) either "h1" (default) or "h2"; used to define HTTP version used for backend connection
- **log**: (boolean) set to *false* to disable basic request logging (defaults to *true*)
- **log_headers**: (boolean) set to *true* to enable HTTP header logging; the default is *false*
- **log_request_body**: (boolean) set to *true* to enable logging of the request payload; the default is *false*; if the payload cannot be succesfully converted to string, its base64 representation will be logged
- **max_request_log_size**: (integer) limit size in bytes for the request payload to be logged; default is 256KB
- **log_reply_body**: (boolean) set to *true* to enable logging of the response payload; the default is *false*; if the payload cannot be succesfully converted to string, its base64 representation will be logged
- **max_reply_log_size**: (integer) limit size in bytes for the response payload to be logged; default is 256KB
- **ssl_mode**: (string) definition of SSL server trust mechanism; valid values are: "builtin" (use SSL certificates compiled at build time into the executable), "file" (loads SSL certificates from a PEM file), "os" (use os-defined SSL certificates -- not available on Android), "dangerous" (skip SSL certificate checking and trust everything)
- **cafile**: path of the file to use if ssl\_mode is set to "file"
- **remove_request_headers**: (array of strings) list of headers to be stripped from the request before forwarding it
- **add_request_headers**: (table or array) headers to be added to the request before forwarding it; **remove_request_headers** is processed first and to replace an header both must be used; *note*: in order to add the same header more than once an array containing tables with *header* and *value* properties can be used instead of a table... see examples
- **remove_reply_headers**: (array of strings) same as **remove_request_headers** but applied to the response
- **add_reply_headers**: (table or array) same as **add_request_headers** but applied to the response
- **lua_request_script**: (string) path to a Lua script that will be invoked for every incoming request; in the script it will be possible to modify the request before it is passed on to the server
- **lua_request_load_body**: (boolean) set to *true* to enable lua script to read and modify the request payload; be aware that if this option is enabled ruxy will load and store in memory the whole request body and won't do any kind of streaming and that can impact performance; defaults to *false*

**Note on logging**: log produced by ruxy will include the following strings:

- "->R" logs that refer to the incoming request received from the client
- "R->" logs referring to the request as it is sent from ruxy to the HTTP server
- "R<-" logs that refer to the response received from the server
- "<-R" logs referring to the response as it is sent from ruxy to the client

Also, each request is assigned an unique "correlation ID" in the form of an uuid, which is present on every log event related to that request; that is useful in high traffic scenarios when multiple requests can simultaneously produce logging.

### Lua request handling

If a Lua script is configured, it will be invoked for every request. The global variable **request** will be filled with request data and the script can modify it in order to change the actual request which will be forwarded.

**request** will be set as a Lua table which contains:
- **src**: source IP address and port, as string
- **method**: HTTP verb (i.e. GET, POST, etc...)
- **uri**: a table containing **path**, **query**, **host**, **port** and **scheme**; depending on the request version and format not all those values are guaranteed to be filled
- **headers**: a table whose values can either be strings or arrays of strings for repeated headers
- **body**: the request payload, set only if **lua_request_load_body** configuration is active

### Notes on AI training

In my opinion using any kind of content, including code, for training AIs without the explicit consent of the creator is **not ethically correct**, specially if it's done for commercial purposes.
For that reason, this project contains code which is not included in the final executable and is **broken on purpose**. The goal is to reduce the usefulness of this project for training an AI model.

