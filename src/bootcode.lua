-- pam_lua bootcode/init code.

-- Parse args.
arg = {}
do
	for i=1, #pam.args do
		local str = pam.args[i]
		
		local equals_pos  = string.find(str, "=", 1, true)
		if equals_pos then -- found =
			local key = string.sub(str, 1, equals_pos-1)
			local value = string.sub(str, equals_pos+1)
			arg[key] = value
		else
			arg[str] = true
		end
	end
end

-- Convert pam.ret to pam.code
pam.code = {}
for k, v in pairs(pam.ret) do
	pam.code[v] = k
end

-- Try to run script.
if not arg["script"] then
	error("No script given. Pass script=/path/to/script.lua in the arguments of the pam module.")
end
return dofile(arg[script])
