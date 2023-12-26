#include "class_data.h"
jclass Java_ex_pkg_Cls_f(JNIEnv* env, jobject obj, jstring str) {
	void* buf;
	size_t bufLen;
	const char* name = env->GetStringUTFChars(str, 0);
	getClassData(name, buf, bufLen); /*Get the class bytes by name*/
	return env->DefineClass(name, obj, buf, bufLen);
} /*

