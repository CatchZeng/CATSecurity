//
//  CATSecurity.h
//  CATSecurity
//
//  Created by Catch on 16/5/11.
//  Copyright © 2016年 catch. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface CATSecurity : NSObject

#pragma mark --
#pragma mark -- MD5

/**
 *  get data's md5 string
 *
 *  @param data source data
 *
 *  @return md5 string
 */
+(NSString *)md5StringWithData:(NSData *)data;

/**
 *  get data's md5 data
 *
 *  @param data source data
 *
 *  @return md5 data
 */
+(NSData *)md5DataWithData:(NSData *)data;

/**
 *  get string's md5 string
 *
 *  @param str source string
 *
 *  @return md5 string
 */
+(NSString *)md5StringWithString:(NSString *)string;

/**
 *  get string's md5 string
 *
 *  @param str source string
 *  @param salt salt string
 *
 *  @return md5 string
 */
+(NSString *)md5StringWithString:(NSString *)str salt:(NSString *)salt;

/**
 *  get string's multiple md5 string
 *
 *  @param str source string
 *
 *  @return md5 string
 */
+(NSString *)md5StringMultipleWithString:(NSString *)str;

/**
 *  get string's disorder md5 string
 *
 *  @param str source string
 *
 *  @return md5 string
 */
+(NSString *)md5StringDisorderWithString:(NSString *)str;

#pragma mark --
#pragma mark -- Base64

/**
 *  get data's base64 encoded string
 *
 *  @param data source data
 *
 *  @return base64 encoded string
 */
+(NSString *)base64EncodedStringWithData:(NSData *)data;

/**
 *  get source data from base64 encoded string
 *
 *  @param base64EncodedString base64 encoded string
 *
 *  @return source data
 */
+(NSData *)dataWithBase64EncodedString:(NSString *)base64EncodedString;

/**
 *  get str's base64 encoded string
 *
 *  @param str source string
 *
 *  @return base64 encoded string
 */
+(NSString *)base64EncodedStringWithString:(NSString *)str;

/**
 *  get source string from base64 encoded string
 *
 *  @param base64EncodedString base64 encoded string
 *
 *  @return source string
 */
+ (NSString *)stringWithBase64EncodedString:(NSString *)base64EncodedString;


#pragma mark --
#pragma mark -- AES

/**
 *  get data's aes256 encrypt data
 *
 *  @param data source data
 *  @param key  key for encrypt/decrypt  !!!key length must be 16
 *
 *  @return aes256 encrypt data
 */
+(NSData *)aes256EncryptWithData:(NSData *)data key:(NSString *)key;

/**
 *  get source data from aes256 encrypt data
 *
 *  @param data aes256 encrypt data
 *  @param key  key for encrypt/decrypt  !!!key length must be 16
 *
 *  @return source data
 */
+(NSData *)aes256DecryptWithData:(NSData *)data key:(NSString *)key;

/**
 *  get string's aes256 encrypt data
 *
 *  @param string source string
 *  @param key  key for encrypt/decrypt  !!!key length must be 16
 *
 *  @return aes256 encrypt data
 */
+(NSData*)aes256EncryptWithString:(NSString*)string key:(NSString *)key;

/**
 *  get source string from aes256 encrypt data
 *
 *  @param data aes256 encrypt data
 *  @param key  key for encrypt/decrypt  !!!key length must be 16
 *
 *  @return source string
 */
+(NSString*)aes256DecryptStringWithData:(NSData *)data key:(NSString *)key;


#pragma mark --
#pragma mark -- RSA

/**
 *  rsa encrypt string with public key
 *
 *  @param str    : source string
 *  @param pubKey : public key
 *
 *  @return base64 encoded string
 */
+ (NSString *)rsaEncryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 *  rsa encrypt data with public key
 *
 *  @param str    : source string
 *  @param pubKey : public key
 *
 *  @return raw data
 */
+ (NSData *)rsaEncryptData:(NSData *)data publicKey:(NSString *)pubKey;

/**
 *  rsa decrypt string with public key
 *
 *  @param str    : base64 encoded string
 *  @param pubKey : public key
 *
 *  @return base64 encoded string
 */
+ (NSString *)rsaDecryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 *  rsa decrypt data with public key
 *
 *  @param data    : encoded data
 *  @param pubKey : public key
 *
 *  @return raw data
 */
+ (NSData *)rsaDecryptData:(NSData *)data publicKey:(NSString *)pubKey;

/**
 *  rsa decrypt string with private key
 *
 *  @param str    : base64 encoded string
 *  @param privKey : private key
 *
 *  @return NSString
 */
+ (NSString *)rsaDecryptString:(NSString *)str privateKey:(NSString *)privKey;

/**
 *  rsa decrypt data with private key
 *
 *  @param data    : encoded data
 *  @param privKey : private key
 *
 *  @return NSData
 */
+ (NSData *)rsaDecryptData:(NSData *)data privateKey:(NSString *)privKey;

@end