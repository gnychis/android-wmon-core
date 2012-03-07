#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <jni.h>
#include "jniexcept.h"

JNIEnv *coexisystEnv;

void
jniExceptionInit(JNIEnv *env)
{
  coexisystEnv = env;
}

void
throwDissectorException(char *file, unsigned int lineno, char *expression)
{
  jclass           exClass;
  char            *className = "java/lang/NoSuchFieldError" ;
  char msg[1024];

  memset(msg, '\0', sizeof(msg));

  exClass = (*coexisystEnv)->FindClass( coexisystEnv, className );
  if ( exClass == NULL )
  {
    abort();
    return;
  }

  snprintf(msg, sizeof(msg), "Error in %s:%u - %s", file, lineno, expression);

  (*coexisystEnv)->ThrowNew( coexisystEnv, exClass, msg);
  return;
}
