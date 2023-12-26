#include <stdio.h>



JNIEXPORT jstring JNICALL Java_com_example_hellojni_HelloJni_stringFromJNI
 (JNIEnv * env, jobject obj) {
    env->DefineClass(env, p1, p2, p3, p4);
    
    globalRef = env->NewGlobalRef(obj);
    // env->DeleteGlobalRef(globalRef)
 }


/**
 * Multi-comments one
 */
int header_main(int argc, int argv) {
    /**
     *
     * Multi-comments two
     */
    printf("I'm example0 app:)\n"); /* Single line comments
    */
    
    
    
    
    // return ok
    return 0;/*
}
