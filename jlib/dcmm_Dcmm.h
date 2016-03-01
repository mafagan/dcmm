/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class dcmm_Dcmm */

#ifndef _Included_dcmm_Dcmm
#define _Included_dcmm_Dcmm
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     dcmm_Dcmm
 * Method:    getStruct
 * Signature: ()Ldcmm/DcmmHeader;
 */
JNIEXPORT jobject JNICALL Java_dcmm_Dcmm_getStruct
  (JNIEnv *, jobject);

/*
 * Class:     dcmm_Dcmm
 * Method:    test
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_dcmm_Dcmm_test
  (JNIEnv *, jobject);

/*
 * Class:     dcmm_Dcmm
 * Method:    init
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_init
  (JNIEnv *, jobject) __attribute__((constructor));

/*
 * Class:     dcmm_Dcmm
 * Method:    destroy
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_dcmm_Dcmm_destroy
  (JNIEnv *, jobject) __attribute__((destructor));

/*
 * Class:     dcmm_Dcmm
 * Method:    socket
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_socket
  (JNIEnv *, jobject, jint);

/*
 * Class:     dcmm_Dcmm
 * Method:    registerSession
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_registerSession
  (JNIEnv *, jobject, jint, jint);

/*
 * Class:     dcmm_Dcmm
 * Method:    connect
 * Signature: (ILdcmm/DcmmAddr;ILdcmm/Timeval;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_connect
  (JNIEnv *, jobject, jint, jobject, jint, jobject);

/*
 * Class:     dcmm_Dcmm
 * Method:    disconnect
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_disconnect
  (JNIEnv *, jobject, jint);

/*
 * Class:     dcmm_Dcmm
 * Method:    sendEx
 * Signature: (I[BJILdcmm/Timeval;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_sendEx
  (JNIEnv *, jobject, jint, jbyteArray, jlong, jint, jobject);

/*
 * Class:     dcmm_Dcmm
 * Method:    send
 * Signature: (I[BJ)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_send
  (JNIEnv *, jobject, jint, jbyteArray, jlong);

/*
 * Class:     dcmm_Dcmm
 * Method:    recvEx
 * Signature: (I[BJILdcmm/Timeval;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_recvEx
  (JNIEnv *, jobject, jint, jbyteArray, jlong, jint, jobject);

/*
 * Class:     dcmm_Dcmm
 * Method:    recv
 * Signature: (I[BJ)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_recv
  (JNIEnv *, jobject, jint, jbyteArray, jlong);

/*
 * Class:     dcmm_Dcmm
 * Method:    status
 * Signature: (ILdcmm/DcmmStatus;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_status
  (JNIEnv *, jobject, jint, jobject);

/*
 * Class:     dcmm_Dcmm
 * Method:    close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_close
  (JNIEnv *, jobject, jint);

/*
 * Class:     dcmm_Dcmm
 * Method:    delete
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_delete
  (JNIEnv *, jobject, jint);

/*
 * Class:     dcmm_Dcmm
 * Method:    tlsSet
 * Signature: (ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_tlsSet
  (JNIEnv *, jobject, jint, jstring, jstring, jstring, jstring);

/*
 * Class:     dcmm_Dcmm
 * Method:    httpHttpsGet
 * Signature: (Ljava/lang/String;[BI)I
 */
JNIEXPORT jint JNICALL Java_dcmm_Dcmm_httpHttpsGet
  (JNIEnv *, jclass, jstring, jbyteArray, jint);

#ifdef __cplusplus
}
#endif
#endif