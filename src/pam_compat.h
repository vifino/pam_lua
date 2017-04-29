// Tiny compat thing for PAM.
// Is it inaccurate? Yes. Yes it is.

#ifndef PAM_BAD_ITEM
  #define PAMC_BAD_ITEM PAM_SYMBOL_ERR
#else
  #define PAMC_BAD_ITEM PAM_BAD_ITEM
#endif

#ifndef PAM_CONV_AGAIN
  #define PAMC_CONV_AGAIN PAM_SYMBOL_ERR
#else
  #define PAMC_CONV_AGAIN PAM_CONV_AGAIN
#endif

#ifndef PAM_INCOMPLETE
  #define PAMC_INCOMPLETE PAM_SYMBOL_ERR
#else
  #define PAMC_INCOMPLETE PAM_INCOMPLETE
#endif
