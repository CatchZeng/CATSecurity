# CATSecurity
iOS &amp; Java (Android、Java Web...) encryption-decryption(AES, MD5)  and coder-decoder(Base64).

code for [iOS安全之路](http://www.jianshu.com/collection/63d04a345984)


##Usage


###MD5

```
    NSString* testSalt = @"1234567890";
    
    NSString* testString = @"123456";
    NSLog(@"testString:%@",testString);
    
    NSData* testData = [testString dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"testData:%@",testData);
    
    NSString* md5String = [CATSecurity md5StringWithData:testData];
    NSLog(@"md5StringWithData:%@",md5String);
    
    NSData* data = [CATSecurity md5DataWithData:testData];
    NSLog(@"md5DataWithData:%@",data);
    
    md5String = [CATSecurity md5StringWithString:testString];
    NSLog(@"md5StringWithString:%@",md5String);
    
    md5String = [CATSecurity md5StringWithString:testString salt:testSalt];
    NSLog(@"md5StringWithString:salt: :%@",md5String);
    
    md5String = [CATSecurity md5StringMultipleWithString:testString];
    NSLog(@"md5StringMultipleWithString:%@",md5String);
    
    md5String = [CATSecurity md5StringDisorderWithString:testString];
    NSLog(@"md5StringDisorderWithString:%@",md5String);
```


###Base64

```

    NSString* testString = @"123456";
    NSLog(@"testString:%@",testString);
    
    NSData* testData = [testString dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"testData:%@",testData);
    
    NSString* base64EncodedString = [CATSecurity base64EncodedStringWithData:testData];
    NSLog(@"base64EncodedStringWithData:%@",base64EncodedString);
    
    NSData* data = [CATSecurity dataWithBase64EncodedString:base64EncodedString];
    NSLog(@"dataWithBase64EncodedString:%@",data);
    
    base64EncodedString = [CATSecurity base64EncodedStringWithString:testString];
    NSLog(@"base64EncodedStringWithString:%@",base64EncodedString);
    
    NSString* str = [CATSecurity stringWithBase64EncodedString:base64EncodedString];
    NSLog(@"stringWithBase64EncodedString:%@",str);

```


###AES

```
    
    NSString* testKey = @"key1233215678987";
        
    NSString* testString = @"123456";
    NSLog(@"testString:%@",testString);
    
    NSData* testData = [testString dataUsingEncoding:NSUTF8StringEncoding];
    NSLog(@"testData:%@",testData);
    
    NSData* data = [CATSecurity aes256EncryptWithData:testData key:testKey];
    NSLog(@"aes256EncryptWithData:key:%@",data);
    //将加密好的data base64编码后传给java
    NSString* base64EncodedString = [CATSecurity base64EncodedStringWithData:data];
    NSLog(@"base64EncodedStringWithData:%@",base64EncodedString);
    
    data = [CATSecurity aes256DecryptWithData:data key:testKey];
    NSLog(@"aes256DecryptWithData:key:%@",data);
    
    data = [CATSecurity aes256EncryptWithString:testString key:testKey];
    NSLog(@"aes256EncryptWithString:key:%@",data);
    //将加密好的data base64编码后传给java
    base64EncodedString = [CATSecurity base64EncodedStringWithData:data];
    NSLog(@"base64EncodedStringWithData:%@",base64EncodedString);
    
    NSString* str = [CATSecurity aes256DecryptStringWithData:data key:testKey];
    NSLog(@"aes256DecryptStringWithData:key:%@",str);

```


###RSA

```

    NSString *pubkey = @"-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDI2bvVLVYrb4B0raZgFP60VXY\ncvRmk9q56QiTmEm9HXlSPq1zyhyPQHGti5FokYJMzNcKm0bwL1q6ioJuD4EFI56D\na+70XdRz1CjQPQE3yXrXXVvOsmq9LsdxTFWsVBTehdCmrapKZVVx6PKl7myh0cfX\nQmyveT/eqyZK1gYjvQIDAQAB\n-----END PUBLIC KEY-----";
    NSString *privkey = @"-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMMjZu9UtVitvgHS\ntpmAU/rRVdhy9GaT2rnpCJOYSb0deVI+rXPKHI9Aca2LkWiRgkzM1wqbRvAvWrqK\ngm4PgQUjnoNr7vRd1HPUKNA9ATfJetddW86yar0ux3FMVaxUFN6F0KatqkplVXHo\n8qXubKHRx9dCbK95P96rJkrWBiO9AgMBAAECgYBO1UKEdYg9pxMX0XSLVtiWf3Na\n2jX6Ksk2Sfp5BhDkIcAdhcy09nXLOZGzNqsrv30QYcCOPGTQK5FPwx0mMYVBRAdo\nOLYp7NzxW/File//169O3ZFpkZ7MF0I2oQcNGTpMCUpaY6xMmxqN22INgi8SHp3w\nVU+2bRMLDXEc/MOmAQJBAP+Sv6JdkrY+7WGuQN5O5PjsB15lOGcr4vcfz4vAQ/uy\nEGYZh6IO2Eu0lW6sw2x6uRg0c6hMiFEJcO89qlH/B10CQQDDdtGrzXWVG457vA27\nkpduDpM6BQWTX6wYV9zRlcYYMFHwAQkE0BTvIYde2il6DKGyzokgI6zQyhgtRJ1x\nL6fhAkB9NvvW4/uWeLw7CHHVuVersZBmqjb5LWJU62v3L2rfbT1lmIqAVr+YT9CK\n2fAhPPtkpYYo5d4/vd1sCY1iAQ4tAkEAm2yPrJzjMn2G/ry57rzRzKGqUChOFrGs\nlm7HF6CQtAs4HC+2jC0peDyg97th37rLmPLB9txnPl50ewpkZuwOAQJBAM/eJnFw\nF5QAcL4CYDbfBKocx82VX/pFXng50T7FODiWbbL4UnxICE0UBFInNNiWJxNEb6jL\n5xd0pcy9O2DOeso=\n-----END PRIVATE KEY-----";
    
    NSString *originString = @"1233211233221133413hdwhfhefhierwjfiwoqjrefijqwerifjioqejwrf";
    
    NSLog(@"Original string(%d): %@", (int)originString.length, originString);
    
    NSString *encWithPubKey = [CATSecurity rsaEncryptString:originString publicKey:pubkey];
    NSLog(@"Enctypted with public key: %@", encWithPubKey);
    
    NSString * decWithPrivKey = [CATSecurity rsaDecryptString:encWithPubKey privateKey:privkey];
    NSLog(@"Decrypted with private key: %@", decWithPrivKey);

```