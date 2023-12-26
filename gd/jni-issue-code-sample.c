#include <stdio.h>

JNIEXPORT jstring JNICALL Java_com_example_hellojni_HelloJni_stringFromJNI
 (JNIEnv * env, jclass obj) {
    env->DefineClass(env, p1, p2, p3, p4);
    
    globalRef = (*env)->NewGlobalRef(env, obj);
    //env->DeleteGlobalRef(env, globalRef)
    
    localRef = (*env)->NewLocalRef(env, obj);
    //env->DeleteLocalRef(env, localRef)
    
    weakRef = (*env)->NewWeakGlobalRef(env, obj);
    //env->DeleteWeakGlobalRef(env, weakRef);
    
    result = (*env)->PushLocalFrame(env, capacity);
    //env->PopLocalFrame(env, result);
    
    chars = (*env)->GetStringChars(env, str, isCopy);
    //(*env)->ReleaseStringChars(env, str, chars);
    
    chars = (*env)->GetStringUTFChars(env, str, isCopy);
    //(*env)->ReleaseStringUTFChars(env, str, chars);
    
    (*env)->MonitorEnter(env, obj);
    //(*env)->MonitorExit(env, obj); 
    
    (*env)->GetBooleanArrayElements(env, array, isCopy);
    //(*env)->ReleaseBooleanArrayElements(env, array, elems, mode);
    
    (*vm)->AttachCurrentThread(vm, p_env, thr_args) 
    //(*vm)->DetachCurrentThread(vm)
    
    JNI_GetDefaultJavaVMInitArgs(void*);
    JNI_CreateJavaVM(JavaVM**, JNIEnv**, void*);
    JNI_GetCreatedJavaVMs(JavaVM**, jsize, jsize*);

    chars = (*env)->GetStringCritical(env, str, isCopy);
    (*env)->MonitorEnter(env, obj);
    //(*env)->MonitorExit(env, obj);
    (*env)->ReleaseStringCritical(env, str, chars);
    
    (*env)->GetPrimitiveArrayCritical(env, array, isCopy);
    //(*env)->MonitorEnter(env, obj);
    (*env)->MonitorExit(env, obj);
    (*env)->ReleasePrimitiveArrayCritical(env, array, carray, mode);
 }
 
 jint JNI_OnLoad(const JavaVM *vm, void* reserved) {
    //
    //
    // return JNI_VERSION_1_2;
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
    
    
    // return ok
    return 0;/*
}
