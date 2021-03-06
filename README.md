# pam_lua

A PAM module scriptable using Lua.

## Dependencies
- Sane OS/Distro
  - GNU/Linux works.
  - FreeBSD works too, but...
    - There are minor differences, but should be OK as long as you don't dive too deep..
- C99 compatible compiler
- Open PAM or Linux PAM. Might work with other PAM variants, dunno.
- Lua libraries (5.1 and luajit tested)
  - Anything above 5.1 should work, hopefully.

## Compiling

`make lua=5.1`

Set `5.1` to whatever Lua version you want to use, according to pkg-config, `5.1`/`-5.1` for Lua 5.1, `jit` for luajit, etc...

## Using

- Copy `pam_lua.so` to `/lib/security` or alternative for wherever your distribution wants PAM modules to reside in.
  - On FreeBSD, copy it to `/usr/lib`.
- Make a Lua script, similar to this (untested) script:
```lua
if pam.handler == "authenticate" then
	local username = pam.get_user()
	local password = pam.readline("Password: ", false) -- password prompt with hidden input
	if username == "user" and password == "letmein" then
		return pam.ret.success -- correct credentials, allow login!
	end
	return pam.ret.perm_denied
else -- not authenticate
	return pam.ret.ignore -- ignore this handler, cause it doesn't apply.
end
```
- Edit a PAM config file and add a line using `pam_lua.so`, say `auth	sufficient	pam_lua.so script=/path/to/script.lua` 
  - Note: If the script is incorrect, you might not be able to log in. If it contains backdoors, someone else might get in...

## Examples

A dynamic MOTD generator I made is here: [motd.lua](https://gist.github.com/vifino/b95713dcdf174ba96aa743264b107ff2).
It ain't the prettiest code-wise, but it does the job. Ships with Clippy!

## API
- `pam.type`
  - The invoked module call type, one of the following:
    - `auth`
    - `account`
    - `session`
    - `password`
- `pam.handler`
  - The PAM hook type, one of the following:
    - `setcred`
    - `authenticate`
    - `acc_mgnt`
    - `open_session`
    - `close_session`
    - `chauthtok`
  - You mostly have to only care about `authenticate`.

- `active = pam.flag[name]`
  - Checks if flag is active.
  - Flags:
    - `silent`: If the service should not generate any messages.
    - when in pam hook `authenticate`:
      - `disallow_null_authtok`: If the service should return `pam.ret.auth_error` when the auth token is null.
    - when in pam hook `setcred`:
      - `establish_cred`: set credentials
      - `delete_cred`: delete credentials
      - `reinitialize_cred`: reinitialize credentials, like resetting password
      - `refresh_cred`: extend lifetime of credentials
    - when in pam hook `chauthtok`:
      - `change_expired_authtok`: only update those passwords if they have aged, otherwise update them unconditionally.

- `user = pam.get_user([login_prompt])`
  - Returns the username, with prompt if not asked before.

- `input[, failure_code] = pam.readline(prompt[, visible])`
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
  - Some important codes:
    - `"ignore"`: Skip handler.
    - `"success"`: Success, allow login/go to next handler.
    - `"perm_denied"`: Permission denied, drop out if handler is required.
    - `"abort"`: Abort.
    - `"try_again"`: Try again!

- `value = pam.getenv(key)`
  - Returns the environment variable in the PAM env.

- `return_code = pam.setenv(key[, value])`
  - Set an environment variable in the PAM env. If value is not given, `key` will be deleted instead of set.

Make sure to return a return code, like `pam.ret.success` or `pam.ret.perm_denied`.

If you do not plan to do anything in a specific PAM hook, return `pam.ret.ignore`.

## License
MIT
