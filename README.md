# pam_lua

A PAM module scriptable using Lua.

## Dependencies
- Sane OS/Distro
- C99 compatible compiler
- PAM
- Lua libraries (5.1 and luajit tested)

## Compiling

`make LUA_VER=5.1`

## Using

- Copy `pam_lua.so` to `/lib/security` or alternative for your distribution.
- Make a Lua script, similar to this (untested) script:
```lua
if pam.type == "authenticate" then
	local username = pam.get_user()
	local password = pam.readline(false, "Password: ")
	if username == "user" and password == "letmein" then
		return pam.ret.success
	end
	return pam.ret.perm_denied
else
	return pam.ret.service_err
end
```
- Edit a PAM config file and add a line using `pam_lua.so`, say `auth	sufficient	pam_lua.so script=/path/to/script.lua` 
  - Note: If the script is incorrect, you might not be able to log in. If it contains backdoors, someone else might get in...

## API
- `pam.type`
  - Returns the PAM hook type, one of the following:
    - `setcred`
    - `authenticate`
    - `acc_mgnt`
    - `open_session`
    - `close_session`
    - `chauthtok`
  - You mostly have to only care about `authenticate`.

- `user = pam.get_user([login_prompt])`
  - Returns the username, with prompt if not asked before.

- `input[, failure_code] = pam.readline(visible, prompt)`
  - Generic text input, if `visible` is `false` then the input is hidden.
  - If getting input fails, it returns `nil, error_code`, which is the numerical representation of a PAM error.

- `return_code = pam.info(text)`
  - Displays info text

- `return_code = pam.error(text)`
  - Displays an error.

- `textual_return_code = pam.code[numerical_return_code]`
  - Looks up the textual return code by a numeric one.

- `numerical_return_code = pam.ret[textual_return_code]`
  - The opposite of the above.

Make sure to return a return code, like `pam.ret.success` or `pam.ret.perm_denied`.

## License
MIT
