
function dump(o)
	if type(o) == 'table' then
		local s = '{'
		for k,v in pairs(o) do
			if type(k) ~= 'number' then k = '"'..k..'"' end
			if string.len(s) > 1 then s = s .. ',' end
			s = s .. ' ['..k..'] = ' .. dump(v)
		end
		return s .. ' }'
	elseif type(o) == 'string' then
		return '"'..tostring(o)..'"'
	else
		return tostring(o)
	end
end

print("Inside LUA script " .. corr_id);
print(dump(request));
request.uri.path = 'hello'

