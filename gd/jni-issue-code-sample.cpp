#include <stdio.h>

JNIEXPORT jstring JNICALL Java_com_example_hellojni_HelloJni_stringFromJNI(JNIEnv * env, jobject obj) {
    env->DefineClass(p1, p2, p3, p4);
    
    globalRef = env->NewGlobalRef(obj);
    //env->DeleteGlobalRef(globalRef);
    
    localRef = env->NewLocalRef(obj);
    //env->DeleteLocalRef(localRef);
    
    weakRef = env->NewWeakGlobalRef(obj);
    //env->DeleteWeakGlobalRef(weakRef);
    
    result = env->PushLocalFrame(capacity);
    //env->PopLocalFrame(result);
    
    chars = env->GetStringChars(str, isCopy);
    //env->ReleaseStringChars(str, chars);
    
    chars = env->GetStringUTFChars(str, isCopy);
    //env->ReleaseStringUTFChars(str, chars);
    
    env->MonitorEnter(obj);
    //env->MonitorExit(obj);
    
    env->GetBooleanArrayElements(array, isCopy)
    //env->ReleaseBooleanArrayElements(array, elems, mode)
    
    vm->AttachCurrentThread(p_env, thr_args) 
    //vm->DetachCurrentThread()
    
    JNI_GetDefaultJavaVMInitArgs(void*);
    JNI_CreateJavaVM(JavaVM**, JNIEnv**, void*);
    JNI_GetCreatedJavaVMs(JavaVM**, jsize, jsize*);
 
    chars = env->GetStringCritical(str, isCopy);
    env->MonitorEnter(obj);
    //env->MonitorExit(obj);
    env)->ReleaseStringCritical(str, chars);
    
    env->GetPrimitiveArrayCritical(array, isCopy);
    //env->MonitorEnter(obj);
    env->MonitorExit(obj);
    env->ReleasePrimitiveArrayCritical(array, carray, mode);
 }


/**
 * Multi-comments one
 */
int main(int argc, int argv) {
    /**
     *
     * Multi-comments two
     */
    printf("I'm example0 app:)\n"); /* Single line comments
    */
    
    
    Java_com_example_hellojni_HelloJni_stringFromJNI(env, obj);
    
    
    // return ok
    return 0;/*
}
