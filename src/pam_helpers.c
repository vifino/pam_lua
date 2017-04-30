////
// PAM helpers
////

// I/O
static int converse(const pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response) {
	struct pam_conv *conv;

	int retval = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
	if (retval == PAM_SUCCESS) {
		retval = conv->conv(nargs, (const struct pam_message**)message, response, conv->appdata_ptr);
	}

	return retval;
}

static int pamh_readline(const pam_handle_t *pamh, int visible, const char* str, char* *res) {
	// Prepare mesg structs
	struct pam_message mesg[1], *pmesg[1];
	pmesg[0] = &mesg[0];

	if (visible != 0) {
		mesg[0].msg_style = PAM_PROMPT_ECHO_ON;
	} else {
		mesg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	}

	mesg[0].msg = (char*)str;

	// Ask
	int retval;
	struct pam_response *resp;
	if ((retval = converse(pamh, 1, pmesg, &resp)) != PAM_SUCCESS) {
		return retval;
	}

	if (resp) {
		char* tres = resp[0].resp;
		*res = calloc(strlen(tres)+1, sizeof(char));
		if (*res == NULL)
			return PAM_BUF_ERR; // allocation failure
		strcpy(*res, tres);
		free(resp[0].resp);
		return PAM_SUCCESS;
	}
	free(resp);
	return PAM_CONV_ERR;
}

static int pamh_info(const pam_handle_t *pamh, const char* str) {
	// Prepare mesg structs
	struct pam_message mesg[1], *pmesg[1];
	pmesg[0] = &mesg[0];

	mesg[0].msg_style = PAM_TEXT_INFO;
	mesg[0].msg = (char*)str;

	// Display text
	int retval;
	struct pam_response *resp;
	if ((retval = converse(pamh, 1, pmesg, &resp)) != PAM_SUCCESS) {
		free(resp);
		return retval;
	}
	free(resp);
	return PAM_SUCCESS;
}

static int pamh_error(const pam_handle_t *pamh, const char* str) {
	// Prepare mesg structs
	struct pam_message mesg[1], *pmesg[1];
	pmesg[0] = &mesg[0];

	mesg[0].msg_style = PAM_ERROR_MSG;
	mesg[0].msg = (char*)str;

	// send error
	int retval;
	struct pam_response *resp;
	if ((retval = converse(pamh, 1, pmesg, &resp)) != PAM_SUCCESS) {
		free(resp);
		return retval;
	}
	free(resp);
	return PAM_SUCCESS;
}

// Items
#define PAM_LUA_PITYPE_STRING 1
#define PAM_LUA_PITYPE_CONV 2
#define PAM_LUA_PITYPE_FAIL_DELAY 3

static int pam_get_itype(const char* iname, int *type) {
	*type = PAM_LUA_PITYPE_STRING;
	if (strcmp(iname, "service"))
		return PAM_SERVICE;
	if (strcmp(iname, "user"))
		return PAM_USER;
	if (strcmp(iname, "user_prompt"))
		return PAM_USER_PROMPT;
	if (strcmp(iname, "tty"))
		return PAM_TTY;
	if (strcmp(iname, "ruser"))
		return PAM_RUSER;
	if (strcmp(iname, "rhost"))
		return PAM_RHOST;
	if (strcmp(iname, "authtok"))
		return PAM_AUTHTOK;
	if (strcmp(iname, "oldauthtok"))
		return PAM_OLDAUTHTOK;
	if (strcmp(iname, "conv")) {
		*type = PAM_LUA_PITYPE_CONV;
		return PAM_CONV;
	}

	// OS specific stuff
#ifdef __linux
	if (strcmp(iname, "authtok_type"))
		return PAM_AUTHTOK_TYPE;
	if (strcmp(iname, "fail_delay")) {
		*type = PAM_LUA_PITYPE_FAIL_DELAY;
		return PAM_FAIL_DELAY;
	}
	if (strcmp(iname, "xdisplay"))
		return PAM_XDISPLAY;
	if (strcmp(iname, "xauthdata"))
		return PAM_XAUTHDATA;
#endif
	return PAM_SYMBOL_ERR;
}
