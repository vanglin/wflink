# Project Wflink

## Description

CMCC combine network process consists of a http server on the lan side and a coap-tls client on the wan side.
The process named **wflink.exe** will handle common interfaces from both sides in the requests of two protocols(lan side using http and wan side using coap).
At the same time, wflink.exe can also initiate a request to the remote coap server for registering/activating/logining/loginouting.
The process named **coapsrv.exe** can simulate the conditions on coap requests from a remote server.
On the other side, using a curl/postman/browser to send http requests is a cinsh.

## Compile

### Compile wflink

make

### Compile test

make coapsrv.exe

## Config file

### Config path

the default config path is /config/wflink.cfg and you can also assign the path by starting the wflink.exe with -f [path]

### Config content

**Note**: bind_address can't be set to '0.0.0.0' or '127.0.0.1' now.

```text
{
	"global": {},
	"http":
	{
		"bind_server_address": "",
		"bind_server_port": 8089
	},
	"coap":
	{
		"bind_client_address": "192.168.234.129",
		"bind_client_port": 6684,
		"proxy_address": "",
		"proxy_server_port": 0,
		"server_address": "",
		"server_port": 5684,
		"transport": "tls",
		"psk_user": "CoAP",
		"psk_key": "secretPSK"
	}
}
```

## Test

Preparation, change all "192.168.234.129" into your PC ip.

First, we start the remote coap server. Second, run our process. Third, try to send a demo reuqest to our process.
**Note**: when the coap server simulates sending msg, fill the url with your coap client ip and port. 

- ./coapsrv.exe -n 240 -v 7
- ./wflink.exe
- ./coapsrv.exe -rx "{\"method\": \"get\", \"url\":\"192.168.234.129:6684/test/helloworld\"}"
