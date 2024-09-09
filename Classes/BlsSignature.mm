#import "BLSSignature.h"

#include <iostream>
#include <bls.hpp>

using namespace bls;

@implementation BlsSignature

// MARK: - Verification

+ (NSString *)augSchemeMplG2Map:(NSString *)hashPublicKey and:(NSString*)hashMessage with:(NSError **)error {
    vector<uint8_t> bytesMessage = Util::HexToBytes([hashMessage cStringUsingEncoding:NSUTF8StringEncoding]);
    vector<uint8_t> bytesPublicKey = Util::HexToBytes([hashPublicKey cStringUsingEncoding:NSUTF8StringEncoding]);
    
    vector<uint8_t> publicHashVector = bytesPublicKey;
    publicHashVector.insert(publicHashVector.end(), bytesMessage.begin(), bytesMessage.end());
    
    std::vector<uint8_t> dst(AugSchemeMPL::CIPHERSUITE_ID.begin(), AugSchemeMPL::CIPHERSUITE_ID.end());
    
    G2Element g2MessageVector = G2Element::FromMessage(publicHashVector, dst.data(), dst.size());
    
    if (g2MessageVector.IsValid() != 1) {
        NSMutableDictionary* details = [NSMutableDictionary dictionary];
        [details setValue:@"hash public key " forKey: @"hashPublicKey"];
        *error = [NSError errorWithDomain:@"world" code: 422 userInfo: details];
    }
    
    std::string g2MessageHash = Util::HexStr(g2MessageVector.Serialize());
    
    return [[NSString alloc] initWithCString:g2MessageHash.c_str() encoding: NSUTF8StringEncoding];
}

+ (NSString *)aggregate: (NSArray<NSString *> *)signatures with:(NSError **)error {
    vector<G2Element> signatureVector;
    
    for (NSString* signature in signatures) {
        vector<uint8_t> bytesSignature = Util::HexToBytes([signature cStringUsingEncoding:NSUTF8StringEncoding]);
        G2Element g2Element = G2Element::FromByteVector(bytesSignature);
        signatureVector.push_back(g2Element);
    }
    
    // Signatures can be non-interactively combined by anyone
    G2Element aggSig = AugSchemeMPL().Aggregate(signatureVector);
    
    if (aggSig.IsValid() != 1) {
        NSMutableDictionary* details = [NSMutableDictionary dictionary];
        [details setValue:@"hash public key " forKey: @"hashPublicKey"];
        *error = [NSError errorWithDomain:@"world" code: 422 userInfo: details];
    }
    
    std::string aggHash = Util::HexStr(aggSig.Serialize());
    
    return [[NSString alloc] initWithCString:aggHash.c_str() encoding: NSUTF8StringEncoding];
}

+ (NSString *)publicKeyFrom:(NSString *)privateKey with:(NSError **)error {
    vector<uint8_t> vectorPrivateKey = Util::HexToBytes([privateKey cStringUsingEncoding:NSUTF8StringEncoding]);
    
    PrivateKey sk = PrivateKey::FromByteVector(vectorPrivateKey);
    
    G2Element popSk = PopSchemeMPL().PopProve(sk);
    std::string hexPopSk = Util::HexStr(popSk.Serialize());
    
    G1Element pk = sk.GetG1Element();
    
    std::string hexPublicKey = Util::HexStr(pk.Serialize());
    
    return [[NSString alloc] initWithCString:hexPublicKey.c_str() encoding: NSUTF8StringEncoding];
}

+ (BOOL)verify: (NSArray<NSString *> *)signatures with:(NSString *)publicKey and:(NSString *)message {
    vector<uint8_t> bytesPublicKey = Util::HexToBytes([publicKey cStringUsingEncoding:NSUTF8StringEncoding]);
    vector<uint8_t> bytesMessage = Util::HexToBytes([message cStringUsingEncoding:NSUTF8StringEncoding]);
    
    vector<G2Element> signatureVector;
    
    for (NSString* signature in signatures) {
        vector<uint8_t> bytesSignature = Util::HexToBytes([signature cStringUsingEncoding:NSUTF8StringEncoding]);
        G2Element g2Element = G2Element::FromByteVector(bytesSignature);
        signatureVector.push_back(g2Element);
    }
    
    // Signatures can be non-interactively combined by anyone
    G2Element aggSig = AugSchemeMPL().Aggregate(signatureVector);
    
    bool isValid = AugSchemeMPL().Verify(bytesPublicKey, bytesMessage, aggSig.Serialize());
    
    return isValid;
}

@end
