
response = {
	status = 200,
	reason = "Lua",
	headers = { ["x-test-lua"] = "handled" },
	body = "Hello " .. request.src .. ", you requested: " .. request.uri.path,
}

