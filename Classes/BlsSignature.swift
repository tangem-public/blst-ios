//
//  BlsKit.swift
//  Bls-Signature
//
//  Created by skibinalexander on 28.07.2023.
//

import Foundation

public struct BlsSignatureSwift {
    
    /// Obtain G2 point for bls curve
    /// - Parameters:
    ///   - publicKey: Public key hash
    ///   - message: Message hash
    /// - Returns: Hash of G2Element point
    public static func augSchemeMplG2Map(publicKey: String, message: String) throws -> String {
        var error: NSError?
        let result = BlsSignature.augSchemeMplG2Map(publicKey, and: message, with: &error)
        
        guard error == nil else {
            throw BlsSignatureSwift.ErrorList.errorAugScheme
        }
        
        return result
    }
    
    /// Perform Aggregate hash signatures
    /// - Parameter signatures: Signatures hash's
    /// - Returns: Hash of result aggreate signature at bls-signature library
    public static func aggregate(signatures: [String]) throws -> String {
        var error: NSError?
        let result = BlsSignature.aggregate(signatures, with: &error)
        
        guard error == nil else {
            throw BlsSignatureSwift.ErrorList.errorAggregate
        }
        
        return result
    }
    
    /// Obtain public key from private key
    /// - Parameter privateKey: Private key hash string
    /// - Returns: Public key hash
    public static func publicKey(from privateKey: String) throws -> String {
        var error: NSError?
        let result = BlsSignature.publicKey(from: privateKey, with: &error)
        
        guard error == nil else {
            throw BlsSignatureSwift.ErrorList.errorPublicKeyFromPrivateKey
        }
        
        return result
    }
    
    /// Verify message payload for signatures
    /// - Parameters:
    ///   - signatures: Hash signatures
    ///   - publicKey: Hash public key
    ///   - message: Has payload message
    /// - Returns: Bool result of valid or no
    public static func verify(signatures: [String], with publicKey: String, message: String) throws -> Bool {
        BlsSignature.verify(signatures, with: publicKey, and: message)
    }

}

public extension BlsSignatureSwift {
    enum ErrorList: Error {
        case errorAggregate
        case errorAugScheme
        case errorPublicKeyFromPrivateKey
        case errorVerify
    }
}
