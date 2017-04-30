////
// Helpers
////

// varargs concat from http://stackoverflow.com/a/11394336 because i don't like varargs much.
static char* concat(int count, ...) {
	va_list ap;
	int i;

	// Find required length to store merged string
	size_t len = 1; // room for \0
	va_start(ap, count);
	for(i=0 ; i<count ; i++)
		len += strlen(va_arg(ap, const char*));
	va_end(ap);

	// Allocate memory to concat strings
	char* merged = calloc(len, sizeof(char));
	if (merged == NULL)
		return NULL;
	int null_pos = 0;

	// Actually concatenate strings
	va_start(ap, count);
	for(i=0 ; i<count ; i++)
	{
		char *s = va_arg(ap, char*);
		strcpy(merged+null_pos, s);
		null_pos += strlen(s);
	}
	va_end(ap);

	return merged;
}
