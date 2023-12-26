#!/usr/bin/env python

import codecs
import getopt
import re
import sys

class _Context(object):

    def __init__(self):
        self.verbose_level = 1
        self.error_count = 0
        self.errors_by_file = {}
        
    def SetVerboseLevel(self, verbose_level):
        self.verbose_level = verbose_level
        
    def VerboseLevel(self):
        return self.verbose_level
    
    def ErrorCount(self):
        return self.error_count
        
    def AddError(self, filename, linenum, message, category, confidence):
        self.error_count += 1
        if filename not in self.errors_by_file:
            self.errors_by_file[filename] = [(linenum, message, category, confidence)]
        else:
            self.errors_by_file[filename].append((linenum, message, category, confidence))   

    def PrintError(self):
        for filename in self.errors_by_file:
            for err in sorted(self.errors_by_file[filename], key=lambda err_item: err_item[0]):  
				err_str = '%s:%s:  %s  [%s] [%d]\n' % ((filename,) +  err)
				n = 0
				for c in err_str:
					n = n + 1
					if c == ' ' and n > 65:
						sys.stderr.write('\n')
						n = 0
					sys.stderr.write(c)   
        sys.stderr.write('Total error: %d\n' % self.error_count)

 
               
_context = _Context()
_regexp_compile_cache = {}

_NATIVE_TYPE = [
    'jboolean', 'jbyte', 'jchar', 'jshort','jint','jlong','jfloat','jdouble','void',
    'jobject', 'jclass', 'jstring', 'jarray', 'jobjectArray', 'jbooleanArray', 'jbyteArray', 'jcharArray'
    'jshortArray', 'jintArray', 'jlongArray', 'jfloatArray', 'jdoubleArray','jthrowable'
]

_PRIMITIVE_TYPE = [
    'Boolean', 'Byte', 'Char', 'Short', 'Int', 'Long', 'Float', 'Double'
]

_NATIVE_INTERFACE = [
	'GetVersion',
	'DefineClass',
	'FindClass',
	'FromReflectedMethod',
	'FromReflectedField',
	'ToReflectedMethod',
	'GetSuperclass',
	'IsAssignableFrom',
	'ToReflectedField',
	'Throw',
	'ThrowNew',
	'ExceptionOccurred',
	'ExceptionDescribe',
	'ExceptionClear',
	'FatalError',
	'PushLocalFrame',
	'PopLocalFrame',
	'NewGlobalRef',
	'DeleteGlobalRef',
	'DeleteLocalRef',
	'IsSameObject',
	'NewLocalRef',
	'EnsureLocalCapacity',
	'AllocObject',
	'NewObject',
	'NewObjectV',
	'NewObjectA',
	'GetObjectClass',
	'IsInstanceOf',
	'GetMethodID',
	'CallObjectMethod',
	'CallObjectMethodV',
	'CallObjectMethodA',
	'CallBooleanMethod',
	'CallBooleanMethodV',
	'CallBooleanMethodA',
	'CallByteMethod',
	'CallByteMethodV',
	'CallByteMethodA',
	'CallCharMethod',
	'CallCharMethodV',
	'CallCharMethodA',
	'CallShortMethod',
	'CallShortMethodV',
	'CallShortMethodA',
	'CallIntMethod',
	'CallIntMethodV',
	'CallIntMethodA',
	'CallLongMethod',
	'CallLongMethodV',
	'CallLongMethodA',
	'CallFloatMethod',
	'CallFloatMethodV',
	'CallFloatMethodA',
	'CallDoubleMethod',
	'CallDoubleMethodV',
	'CallDoubleMethodA',
	'CallVoidMethod',
	'CallVoidMethodV',
	'CallVoidMethodA',
	'CallNonvirtualObjectMethod',
	'CallNonvirtualObjectMethodV',
	'CallNonvirtualObjectMethodA',
	'CallNonvirtualBooleanMethod',
	'CallNonvirtualBooleanMethodV',
	'CallNonvirtualBooleanMethodA',
	'CallNonvirtualByteMethod',
	'CallNonvirtualByteMethodV',
	'CallNonvirtualByteMethodA',
	'CallNonvirtualCharMethod',
	'CallNonvirtualCharMethodV',
	'CallNonvirtualCharMethodA',
	'CallNonvirtualShortMethod',
	'CallNonvirtualShortMethodV',
	'CallNonvirtualShortMethodA',
	'CallNonvirtualIntMethod',
	'CallNonvirtualIntMethodV',
	'CallNonvirtualIntMethodA',
	'CallNonvirtualLongMethod',
	'CallNonvirtualLongMethodV',
	'CallNonvirtualLongMethodA',
	'CallNonvirtualFloatMethod',
	'CallNonvirtualFloatMethodV',
	'CallNonvirtualFloatMethodA',
	'CallNonvirtualDoubleMethod',
	'CallNonvirtualDoubleMethodV',
	'CallNonvirtualDoubleMethodA',
	'CallNonvirtualVoidMethod',
	'CallNonvirtualVoidMethodV',
	'CallNonvirtualVoidMethodA',
	'GetFieldID',
	'GetObjectField',
	'GetBooleanField',
	'GetByteField',
	'GetCharField',
	'GetShortField',
	'GetIntField',
	'GetLongField',
	'GetFloatField',
	'GetDoubleField',
	'SetObjectField',
	'SetBooleanField',
	'SetByteField',
	'SetCharField',
	'SetShortField',
	'SetIntField',
	'SetLongField',
	'SetFloatField',
	'SetDoubleField',
	'GetStaticMethodID',
	'CallStaticObjectMethod',
	'CallStaticObjectMethodV',
	'CallStaticObjectMethodA',
	'CallStaticBooleanMethod',
	'CallStaticBooleanMethodV',
	'CallStaticBooleanMethodA',
	'CallStaticByteMethod',
	'CallStaticByteMethodV',
	'CallStaticByteMethodA',
	'CallStaticCharMethod',
	'CallStaticCharMethodV',
	'CallStaticCharMethodA',
	'CallStaticShortMethod',
	'CallStaticShortMethodV',
	'CallStaticShortMethodA',
	'CallStaticIntMethod',
	'CallStaticIntMethodV',
	'CallStaticIntMethodA',
	'CallStaticLongMethod',
	'CallStaticLongMethodV',
	'CallStaticLongMethodA',
	'CallStaticFloatMethod',
	'CallStaticFloatMethodV',
	'CallStaticFloatMethodA',
	'CallStaticDoubleMethod',
	'CallStaticDoubleMethodV',
	'CallStaticDoubleMethodA',
	'CallStaticVoidMethod',
	'CallStaticVoidMethodV',
	'CallStaticVoidMethodA',
	'GetStaticFieldID',
	'GetStaticObjectField',
	'GetStaticBooleanField',
	'GetStaticByteField',
	'GetStaticCharField',
	'GetStaticShortField',
	'GetStaticIntField',
	'GetStaticLongField',
	'GetStaticFloatField',
	'GetStaticDoubleField',
	'SetStaticObjectField',
	'SetStaticBooleanField',
	'SetStaticByteField',
	'SetStaticCharField',
	'SetStaticShortField',
	'SetStaticIntField',
	'SetStaticLongField',
	'SetStaticFloatField',
	'SetStaticDoubleField',
	'NewString',
	'GetStringLength',
	'GetStringChars',
	'ReleaseStringChars',
	'NewStringUTF',
	'GetStringUTFLength',
	'GetStringUTFChars',
	'ReleaseStringUTFChars',
	'GetArrayLength',
	'NewObjectArray',
	'GetObjectArrayElement',
	'SetObjectArrayElement',
	'NewBooleanArray',
	'NewByteArray',
	'NewCharArray',
	'NewShortArray',
	'NewIntArray',
	'NewLongArray',
	'NewFloatArray',
	'NewDoubleArray',
	'GetBooleanArrayElements',
	'GetByteArrayElements',
	'GetCharArrayElements',
	'GetShortArrayElements',
	'GetIntArrayElements',
	'GetLongArrayElements',
	'GetFloatArrayElements',
	'GetDoubleArrayElements',
	'ReleaseBooleanArrayElements',
	'ReleaseByteArrayElements',
	'ReleaseCharArrayElements',
	'ReleaseShortArrayElements',
	'ReleaseIntArrayElements',
	'ReleaseLongArrayElements',
	'ReleaseFloatArrayElements',
	'ReleaseDoubleArrayElements',
	'GetBooleanArrayRegion',
	'GetByteArrayRegion',
	'GetCharArrayRegion',
	'GetShortArrayRegion',
	'GetIntArrayRegion',
	'GetLongArrayRegion',
	'GetFloatArrayRegion',
	'GetDoubleArrayRegion',
	'SetBooleanArrayRegion',
	'SetByteArrayRegion',
	'SetCharArrayRegion',
	'SetShortArrayRegion',
	'SetIntArrayRegion',
	'SetLongArrayRegion',
	'SetFloatArrayRegion',
	'SetDoubleArrayRegion',
	'RegisterNatives',
	'UnregisterNatives',
	'MonitorEnter',
	'MonitorExit',
	'GetJavaVM',
	'GetStringRegion',
	'GetStringUTFRegion',
	'GetPrimitiveArrayCritical',
	'ReleasePrimitiveArrayCritical',
	'GetStringCritical',
	'ReleaseStringCritical',
	'NewWeakGlobalRef',
	'DeleteWeakGlobalRef',
	'ExceptionCheck',
	'NewDirectByteBuffer',
	'GetDirectBufferAddress',
	'GetDirectBufferCapacity',
	'GetObjectRefType'
]

_INVOKE_INTERFACE = [
    'DestroyJavaVM',
    'AttachCurrentThread',
    'DetachCurrentThread',
    'GetEnv',
    'AttachCurrentThreadAsDaemon'
]

_USAGE = """
Usage: cppchecker.py [--help] [--verbose=1|2|3|4|5] <file> [file] ...

    Options:

    	--help
            Display this usage.

    	--verbose=1|2|3|4|5
            Specify the verbosity levels: 1-5 (default is 1).
      		
"""
     
def PrintUsage(message):
    sys.stderr.write(_USAGE)
    if message:
        sys.exit('\nERROR: ' + message)
    else:
        sys.exit(1)

def ParseArguments(args):
    try:
        (opts, files) = getopt.getopt(args, '', ['help', 'verbose='])
    except getopt.GetoptError:
        PrintUsage('Invalid arguments.')
    
    verbose_level = 1  
    for (opt, val) in opts:
        if opt == '--help':
            PrintUsage(None)
        elif opt == '--verbose':
            verbose_level = int(val)
                
    if not files:
        PrintUsage('No files were specified.')

    cpp_files, c_files, h_files = [], [], []
    for f in files:
        try:
            codecs.open(f, 'r', 'utf8', 'replace').read()
            if f.endswith(".cpp"):
                cpp_files.append(f)
            elif f.endswith(".c"):
                c_files.append(f)
            elif f.endswith(".h"):
                h_files.append(f)
            else:
                sys.stderr.write("Skip checking '%s': is not a .c or .cpp file\n" % f)
        except IOError:
            sys.stderr.write("Skip checking '%s': can't open for reading\n" % f)
          
    if not cpp_files and not c_files:
        sys.stderr.write("No files will be checked.\n")
        sys.exit(1)
        
    return verbose_level, cpp_files, c_files, h_files
    
def SetVerboseLevel(verbose_level):
    _context.SetVerboseLevel(verbose_level)
        
def ShouldPrintError(category, confidence):
    if confidence >= _context.VerboseLevel():
        return True
    return False

def Error(filename, linenum, category, confidence, message):
    if ShouldPrintError(category, confidence):
        _context.AddError(filename, linenum, message, category, confidence)

def Match(pattern, s, flags=0):
    """Matches the string with the pattern, caching the compiled regexp."""
    # The regexp compilation caching is inlined in both Match and Search for
    # performance reasons; factoring it out into a separate function turns out
    # to be noticeably expensive.
    if pattern not in _regexp_compile_cache:
        _regexp_compile_cache[pattern] = re.compile(pattern, flags)
    return _regexp_compile_cache[pattern].match(s)
    
    
def Search(pattern, s, flags=0):
    if pattern not in _regexp_compile_cache:
        _regexp_compile_cache[pattern] = re.compile(pattern, flags)
    return _regexp_compile_cache[pattern].search(s)
    
  
def CheckDefineClass(filename, file_str, error):
    # DefineClass is not supported by android
    # jclass DefineClass(JNIEnv *env, const char *name, jobject loader,
    #                  const jbyte *buf, jsize bufLen);
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('\s*->\s*DefineClass\s*\((\s*.*?\s*\,){4}\s*.*?\s*\)', file_str)  
    elif file_extension == 'cpp':
        m = Search('\s*->\s*DefineClass\s*\((\s*.*?\s*\,){3}\s*.*?\s*\)', file_str)
    else:
        m = Search('\s*->\s*DefineClass\s*\((\s*.*?\s*\,){3,4}\s*.*?\s*\)', file_str)
    if m:
        error(filename, Pos2LineNumber(file_str, m.start()), 'unsupported', 5,
            r"Android doesn't support 'DefineClass' JNI function")  

def CheckGlobalJavaVM(filename, file_str, error):
    # In practice, these are not exported by the NDK
    # jint JNI_GetDefaultJavaVMInitArgs(void*);
    # jint JNI_CreateJavaVM(JavaVM**, JNIEnv**, void*);
    # jint JNI_GetCreatedJavaVMs(JavaVM**, jsize, jsize*);
    m = Search('JNI_GetDefaultJavaVMInitArgs\s*\(\s*.*?\s*\)', file_str)
    if m:
        error(filename, Pos2LineNumber(file_str, m.start()), 'unsupported', 3,
            r"'JNI_GetDefaultJavaVMInitArgs' is not exported by Android NDK")
            
    m = Search('JNI_CreateJavaVM\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)', file_str)
    if m:
        error(filename, Pos2LineNumber(file_str, m.start()), 'unsupported', 3,
            r"'JNI_CreateJavaVM' is not exported by the Android NDK")   
    
    m = Search('JNI_GetCreatedJavaVMs\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)', file_str)
    if m:
        error(filename, Pos2LineNumber(file_str, m.start()), 'unsupported', 3,
            r"'JNI_GetCreatedJavaVMs' is not exported by Android NDK") 

def CheckLocalRef(filename, file_str, error):
    # jobject NewLocalRef(JNIEnv *env, jobject obj);
    # void DeleteLocalRef(JNIEnv *env, jobject localRef);
    # If the former is called, the latter must also be invoked
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('\s*->\s*NewLocalRef\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str) 
        if m and not Search('\s*->\s*DeleteLocalRef\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'reference', 2,
                r"'NewLocalRef' is called, better to call 'DeleteLocalRef' to avoid VM Out Of Memory")   
    elif file_extension == 'cpp': 
        m = Search('\s*->\s*NewLocalRef\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str)
        if m and not Search('\s*->\s*DeleteLocalRef\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'reference', 2,
                r"'NewLocalRef' is called, better to call 'DeleteLocalRef' to avoid VM Out Of Memory")   


def CheckGlobalRef(filename, file_str, error):
    # jobject NewGlobalRef(JNIEnv *env, jobject obj);
    # void DeleteGlobalRef(JNIEnv *env, jobject globalRef);
    # If the former is called, the latter must also be invoked
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('\s*\->\s*NewGlobalRef\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str) 
        if m and not Search('\s*\->\s*DeleteGlobalRef\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'reference', 3,
                r"'NewGlobalRef' is called, but 'DeleteGlobalRef' is not invoked") 
    elif file_extension == 'cpp': 
        m = Search('\s*\->\s*NewGlobalRef\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str)
        if m and not Search('\s*\->\s*DeleteGlobalRef\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'reference', 3,
                r"'NewGlobalRef' is called, but 'DeleteGlobalRef' is not invoked")
                
                        
def CheckWeakGlobalRef(filename, file_str, error):
    # jweak NewWeakGlobalRef(JNIEnv *env, jobject obj);
    # void DeleteWeakGlobalRef(JNIEnv *env, jweak obj);
    # If the former is called, the latter better to be invoked
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('\s*->\s*NewWeakGlobalRef\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str) 
        if m and not Search('\s*->\s*DeleteWeakGlobalRef\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'reference', 1,
                r"'NewWeakGlobalRef' is called, better to call 'DeleteWeakGlobalRef'") 
    elif file_extension == 'cpp': 
        m = Search('\s*->\s*NewWeakGlobalRef\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str)
        if m and not Search('\s*->\s*DeleteWeakGlobalRef\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'reference', 1,
                r"'NewWeakGlobalRef' is called,  better to call 'DeleteWeakGlobalRef'")     


def CheckLocalFrame(filename, file_str, error):
    # jint PushLocalFrame(JNIEnv *env, jint capacity);
    # object PopLocalFrame(JNIEnv *env, jobject result);
    # If the former is called, the latter must also be invoked
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('s*->\s*PushLocalFrame\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str) 
        if m and not Search('\s*->\s*PopLocalFrame\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'local-frame', 5,
                r"'PushLocalFrame' is called, but 'PopLocalFrame' is not invoked")  
    elif file_extension == 'cpp': 
        m = Search('\s*->\s*PushLocalFrame\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str)
        if m and not Search('\s*->\s*PopLocalFrame\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'local-frame', 5,
                r"'PushLocalFrame' is called, but 'PopLocalFrame' is not invoked'") 


def CheckStringChars(filename, file_str, error):
    # const jchar * GetStringChars(JNIEnv *env, jstring string, jboolean *isCopy);
    # void ReleaseStringChars(JNIEnv *env, jstring string, const jchar *chars);
    # If the former is called, the latter better to be invoked
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('s*->\s*GetStringChars\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)', file_str) 
        if m and not Search('\s*->\s*ReleaseStringChars\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'string', 3,
                r"'GetStringChars' is called, better to call 'ReleaseStringChars' to avoid memory leak") 
    elif file_extension == 'cpp': 
        m = Search('\s*->\s*GetStringChars\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)', file_str)
        if m and not Search('\s*->\s*ReleaseStringChars\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'string', 3,
                r"'GetStringChars' is called, better to call 'ReleaseStringChars' to avoid memory leak")  
  
def CheckStringUTFChars(filename, file_str, error):
    # const jchar * GetStringUTFChars(JNIEnv *env, jstring string, jboolean *isCopy);
    # void ReleaseStringUTFChars(JNIEnv *env, jstring string, const jchar *chars);
    # If the former is called, the latter better to be invoked
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('s*->\s*GetStringUTFChars\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)', file_str) 
        if m and not Search('\s*->\s*ReleaseStringUTFChars\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'string', 3,
                r"'GetStringUTFChars' is called, better to call 'ReleaseStringUTFChars' to avoid memory leak") 
    elif file_extension == 'cpp': 
        m = Search('\s*->\s*GetStringUTFChars\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)', file_str)
        if m and not Search('\s*->\s*ReleaseStringUTFChars\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'string', 3,
                r"'GetStringUTFChars' is called, better to call 'ReleaseStringUTFChars' to avoid memory leak")
   
def CheckMonitor(filename, file_str, error):       
    # jint MonitorEnter(JNIEnv *env, jobject obj);
    # jint MonitorExit(JNIEnv *env, jobject obj); 
    # If the former is called, the latter must be invoked
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('s*\->s*MonitorEnter\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str) 
        if m and not Search('\s*->\s*MonitorExit\s*\((\s*.*?\s*\,){1}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'monitor', 5,
                r"'MonitorEnter' is called, better to call 'MonitorExit' to avoid thread block or deadlock") 
    elif file_extension == 'cpp': 
        m = Search('\s*->\s*MonitorEnter\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str)
        if m and not Search('\s*->\s*MonitorExit\s*\((\s*.*?\s*\,){0}\s*\w+\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'monitor', 5,
                r"'MonitorEnter' is called, better to 'MonitorExit' to thread block or deadlock")
 
def CheckArrayElements(filename, file_str, error):
    # NativeType *Get<PrimitiveType>ArrayElements(JNIEnv *env,
    #   ArrayType array, jboolean *isCopy)
    # void Release<PrimitiveType>ArrayElements(JNIEnv *env,
    #   ArrayType array, NativeType *elems, jint mode)
    # If the former is called, the latter should be invoked
    file_extension = filename[filename.rfind('.') + 1:]
    
    get_c_p = 's*->Get(' + '|'.join(_PRIMITIVE_TYPE) + ')ArrayElements\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)'
    get_cpp_p = 's*->Get(' + '|'.join(_PRIMITIVE_TYPE) + ')ArrayElements\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)'
    release_c_p = 's*->Release(' + '|'.join(_PRIMITIVE_TYPE) + ')ArrayElements\s*\((\s*.*?\s*\,){3}\s*.*?\s*\)'
    release_cpp_p = 's*->Release(' + '|'.join(_PRIMITIVE_TYPE) + ')ArrayElements\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)'
    
    if file_extension == 'c':
        m = Search(get_c_p, file_str) 
        if m and not Search(release_c_p, file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'array', 3,
                 r"'Get" + m.group(1) + r"ArrayElements' is called, "
                 + r"better to call 'Release" + m.group(1) + r"ArrayElements' to avoid memory leak") 
    elif file_extension == 'cpp': 
        m = Search(get_cpp_p, file_str)
        if m and not Search(release_cpp_p, file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'array', 3,
                 r"'Get" + m.group(1) + r"ArrayElements' is called, "
                 + r"better to call 'Release" + m.group(1) + r"ArrayElements' to avoid memory leak")
                
    
def CheckCurrentThread(filename, file_str, error):
    # jint AttachCurrentThread(JavaVM* vm, JNIEnv** p_env, void* thr_args) 
    # jint DetachCurrentThread(JavaVM* vm)
    # If the former is called, the latter seems need invokation
    file_extension = filename[filename.rfind('.') + 1:]
    if file_extension == 'c':
        m = Search('s*->\s*AttachCurrentThread\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)', file_str) 
        if m and not Search('\s*->\s*DetachCurrentThread\s*\(\s*.*?\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'thread', 2,
                r"'AttachCurrentThread' is called, consider invoke 'DetachCurrentThread' if necessary") 
    elif file_extension == 'cpp': 
        m = Search('\s*->\s*AttachCurrentThread\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)', file_str)
        if m and not Search('\s*->\s*DetachCurrentThread\s*\(\s*\)', file_str):
            error(filename, Pos2LineNumber(file_str, m.start()), 'thread', 2,
                r"'AttachCurrentThread' is called, consider invoke 'DetachCurrentThread' if necessary") 

def CheckJNIFunctions(filename, file_str, error):
    name_p = '(' + '|'.join(_NATIVE_INTERFACE + _INVOKE_INTERFACE) + ')'
    call_p = '\s*->\s*' + name_p + '\s*\((\s*.*?\s*)(,\s*.*?\s*)*\)'
    include_p = '$#\s*include\s["<]\s*jni.h\s*[">]\s*^'
    file_extension = filename[filename.rfind('.') + 1:]
    
    
    if file_extension == 'h':
        m = Search(call_p, file_str)
        if m:
            function_name = m.group(1)
            error(filename, Pos2LineNumber(file_str, m.start()), 'jni-function', 3,
               r"Call JNI function '" + function_name + r"' in a .h file is error-prone") 
    if file_extension == 'cpp':
        m = Search(call_p, file_str)
        if m and (not Search(include_p, file_str)):
            function_name = m.group(1) 
            error(filename, Pos2LineNumber(file_str, m.start()), 'jni-function', 1,
               r"JNI function '" + function_name + r"' is invoked, suggest adding '#include <jni.h>'") 
    if file_extension == 'c':
        m = Search(call_p, file_str)
        if m and (not Search(include_p, file_str)):
            function_name = m.group(1) 
            error(filename, Pos2LineNumber(file_str, m.start()), 'jni-function', 1,
               r"JNI function '" + function_name + r"' is invoked, suggest adding '#include <jni.h>'")             
    
def FindCloseSymbol(s, search_pos, open_symbol, close_symbol):
    search_str = s[search_pos:]
    open_symbol_count = 0
    for i in range(0, len(search_str)):
        if search_str[i] == open_symbol:
            open_symbol_count += 1
        elif search_str[i] == close_symbol:
            open_symbol_count -= 1
            if open_symbol_count == 0:
                return search_pos + i
    return -1
        
def CheckJavaNativeMethods(filename, file_str, error):
    # java native method has the following like signature
    # JNIEXPORT jstring JNICALL Java_com_example_hellojni_HelloJni_stringFromJNI
    #  (JNIEnv*, jobject, ...);    
    ret_type_p = '(' + '|'.join(_NATIVE_TYPE) + ')'
    params_p = '\(\s*JNIEnv\s*\*\s*(\w+)?,\s*(jobject|jclass)\s*(\w+)?(,.*?)*\)'
    name_p = '(Java(_\w+){3,}(__\w+(_\w+)*)*)' 
    method_imp_p1 = '(JNIEXPORT\s+)*' + ret_type_p + '(\s+JNICALL)*\s+' + '(Java_.*?)' + '\s*' + params_p + "\s*\{" 
    method_imp_p2 = '(JNIEXPORT\s+)*' + ret_type_p + '(\s+JNICALL)*\s+' + name_p + '\s*' + '(\(.*?\))' + "\s*\{"
    m = Search(method_imp_p1, file_str)
    if m:
        name_val = m.group(4);
        if not Search(name_p, name_val):
            error(filename, Pos2LineNumber(file_str, m.start), 'java-native-method', 1,
                r"Is '" + name_val  + r"' a java native method ? If yes, its name is incorrect")   
    m = Search(method_imp_p2, file_str)
    if m:
        name_val = m.group(4)
        params_val = str(m.group(8))
        if not Search(params_p, params_val):
            error(filename, Pos2LineNumber(file_str, m.start), 'java-native-method', 1,
                r"Is '" + name_val  + r"' a java native method? If yes, its parameter is incorrect") 
   
def CheckCritical(filename, file_str, error):
    # Any JNI function can't be invoked between the following pairs
    # 1) const jchar * GetStringCritical(JNIEnv *env, jstring string, jboolean *isCopy);
    #    void ReleaseStringCritical(JNIEnv *env, jstring string, const jchar *carray);
    # 2) void * GetPrimitiveArrayCritical(JNIEnv *env, jarray array, jboolean *isCopy);
    #    void ReleasePrimitiveArrayCritical(JNIEnv *env, jarray array, void *carray, jint mode);
    name_p = '(' + '|'.join(_NATIVE_INTERFACE + _INVOKE_INTERFACE) + ')'
    jni_call_p = '\s*->\s*' + name_p + '\s*\((\s*.*?\s*)(,\s*.*?\s*)*\)'
    
    get_string_c_p = 's*->\s*GetStringCritical\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)'
    release_string_c_p = '\s*->\s*ReleaseStringCritical\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)'
    jni_call_in_string_c_p = get_string_c_p + '.*?' + jni_call_p + '.*?'  + release_string_c_p
    
    get_array_c_p = 's*->\s*GetPrimitiveArrayCritical\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)'
    release_array_c_p = '\s*->\s*ReleasePrimitiveArrayCritical\s*\((\s*.*?\s*\,){3}\s*.*?\s*\)'
    jni_call_in_array_c_p = get_array_c_p + '.*?' + jni_call_p + '.*?'  + release_array_c_p
    
    get_string_cpp_p = 's*->\s*GetStringCritical\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)'
    release_string_cpp_p ='\s*->\s*ReleaseStringCritical\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)'
    jni_call_in_string_cpp_p = get_string_cpp_p + ".*?" + jni_call_p + ".*?" + release_string_cpp_p
    
    get_array_cpp_p = 's*->\s*GetPrimitiveArrayCritical\s*\((\s*.*?\s*\,){1}\s*.*?\s*\)'
    release_array_cpp_p ='\s*->\s*ReleasePrimitiveArrayCritical\s*\((\s*.*?\s*\,){2}\s*.*?\s*\)'
    jni_call_in_array_cpp_p = get_array_cpp_p + ".*?" + jni_call_p + ".*?" + release_array_cpp_p
    
    file_extension = filename[filename.rfind('.') + 1:]
    m1, m2, m3, m4, m5, m6 = None, None, None, None, None, None
    if file_extension == 'h':
        pass
    elif file_extension == 'c':
        m1 = Search(get_string_c_p, file_str)
        m2 = Search(release_string_c_p, file_str)
        m3 = Search(jni_call_in_string_c_p, file_str, re.DOTALL)
        m4 = Search(get_array_c_p, file_str)
        m5 = Search(release_array_c_p, file_str)
        m6 = Search(jni_call_in_array_c_p, file_str, re.DOTALL)
  
    elif file_extension == 'cpp':
        m1 = Search(get_string_cpp_p, file_str)
        m2 = Search(release_string_cpp_p, file_str)
        m3 = Search(jni_call_in_string_cpp_p, file_str, re.DOTALL)
        m4 = Search(get_array_cpp_p, file_str)
        m5 = Search(release_array_cpp_p, file_str)
        m6 = Search(jni_call_in_array_cpp_p, file_str, re.DOTALL)
    if m1 and not m2:
        error(filename, Pos2LineNumber(file_str, m1.start()), 'critical', 2,
            r"'GetStringCritical' is called, better to call 'ReleaseStringCritical' to avoid memory leak")
    if m3:
        error(filename, Pos2LineNumber(file_str, m3.start(2)), 'critical', 5,
             r"JNI function '" + m3.group(2) + r"' can't be called between 'GetStringCritical' and 'ReleaseStringCritical'") 
    if m4 and not m5:
        error(filename, Pos2LineNumber(file_str, m4.start()), 'critical', 2,
            r"'GetPrimitiveArrayCritical' is called, better to call 'ReleasePrimitiveArrayCritical' to avoid memory leak")
    if m6:
        error(filename, Pos2LineNumber(file_str, m6.start(2)), 'critical', 5,
             r"JNI function '" + m6.group(2) + r"' can't be called between 'GetPrimitiveArrayCritical' and 'ReleasePrimitiveArrayCritical'") 
  
def CheckOnLoad(filename, file_str, error):
    # JNI_OnLoad Must return a value
    # jint JNI_OnLoad(JavaVM *vm, void *reserved);
    return_type_p ='jint'
    params_p = '\s*JavaVM\s*\*\s*(\w+)?\s*,\s*void\s*\*\s*(\w+)?\s*'  
    method_imp_p = '\s+(\w+)\s+JNI_OnLoad\s*\((.*?)\)\s*?\{'
    m = Search(method_imp_p, file_str)
    if m:
        return_val = m.group(1)
        params_val = m.group(2)
        if not Search(return_type_p, return_val) or not Search(params_p, params_val):
            error(filename, Pos2LineNumber(file_str, m.start()), 'onload', 1,
                r"'JNI_OnLoad' signature should be 'jint JNI_OnLoad(JavaVM *vm, void *reserved)'")
                
        end_pos = FindCloseSymbol(file_str, m.end()-1, '{', '}') 
        if end_pos != -1:
            if not Search('return.*?;', file_str[m.start():end_pos]):
                error(filename, Pos2LineNumber(file_str, m.start()), 'onload', 5,
                    r"'JNI_OnLoad' has no return value") 
   
def Pos2LineNumber(file_str, pos):
    line_num = 1
    for i in range(0, len(file_str)):
        if file_str[i] == '\n' and i <= pos:
            line_num += 1
    return line_num
    
def LRCount(comments):
    return len(comments.split('\n')) - 1
       
def RemoveComments(filename, file_str, error):
    p0 = file_str.find("/*")
    p1 = file_str.find("//")

    while p0 != -1 or p1 != -1:
        if p0 == -1 or (p1 != -1 and p1 < p0) :
            p = file_str.find("\n", p1+2)
            if p == -1:
                file_str = file_str[:p1] + LRCount(file_str[p1:])*'\n'
                return file_str
            file_str = file_str[:p1] + LRCount(file_str[p1:p])*'\n' + file_str[p:]
        else:
            p = file_str.find("*/", p0+2)
            if p == -1:
                error(filename, Pos2LineNumber(file_str, p0), 'comments', 5,
                    r"Comments '/*' found, but '*/' not found in this file")
                file_str = file_str[:p0] + LRCount(file_str[p0:])*'\n'
                return file_str
            else:
                file_str = file_str[:p0] + + LRCount(file_str[p0:p+2])*'\n' + file_str[p+2:]
        
        p0 = file_str.find("/*")
        p1 = file_str.find("//")
        
    return file_str
    
def RemoveCRLF(filename, error):
    lf_lines = []
    crlf_lines = []
    lines = codecs.open(filename, 'r', 'utf8', 'replace').read().split('\n')

    # Remove trailing '\r'.
    # The -1 accounts for the extra trailing blank line we get from split()
    for linenum in range(len(lines) - 1):
        if lines[linenum].endswith('\r'):
            lines[linenum] = lines[linenum].rstrip('\r')
            crlf_lines.append(linenum + 1)
        else:
            lf_lines.append(linenum + 1)
            
    if lf_lines and crlf_lines:
        # Warn on every line with CR.  An alternative approach might be to
        # check whether the file is mostly CRLF or just LF, and warn on the
        # minority, we bias toward LF here since most tools prefer LF.
        for linenum in crlf_lines:
            error(filename, linenum, 'newline', 1,
              'Unexpected \\r (^M) found; better to use only \\n')

    return '\n'.join(lines)
    
    
def ProcessFile(filename, error):
    file_str = RemoveCRLF(filename, error)
    file_str = RemoveComments(filename, file_str, error)

    CheckGlobalJavaVM(filename, file_str, error)
    CheckDefineClass(filename, file_str, error)
    CheckLocalRef(filename, file_str, error)
    CheckGlobalRef(filename, file_str, error)
    CheckWeakGlobalRef(filename, file_str, error)
    CheckLocalFrame(filename, file_str, error)
    CheckStringChars(filename, file_str, error)
    CheckStringUTFChars(filename, file_str, error)
    CheckMonitor(filename, file_str, error)
    CheckArrayElements(filename, file_str, error)
    CheckCurrentThread(filename, file_str, error)
    CheckCritical(filename, file_str, error)
    CheckJNIFunctions(filename, file_str, error)
    CheckOnLoad(filename, file_str, error)
    CheckJavaNativeMethods(filename, file_str, error)
    
def ProcessFiles(cpp_files, c_files, h_files):
    for f in cpp_files + c_files + h_files:
        ProcessFile(f, Error) 
        
def main():
    verbose_level, cpp_files, c_files, h_files = ParseArguments(sys.argv[1:])
    SetVerboseLevel(verbose_level)
    ProcessFiles(cpp_files, c_files, h_files)

    # Change stderr to write with replacement characters so we don't die
    # if we try to print something containing non-ASCII characters.
    sys.stderr = codecs.StreamReaderWriter(sys.stderr,
                                           codecs.getreader('utf8'),
                                           codecs.getwriter('utf8'),
                                           'replace') 
    if _context.ErrorCount() > 0:
        _context.PrintError()

    sys.exit(_context.ErrorCount())

if __name__ == '__main__':
    main()
