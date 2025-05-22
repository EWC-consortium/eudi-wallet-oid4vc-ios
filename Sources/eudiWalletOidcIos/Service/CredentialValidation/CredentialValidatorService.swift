//
//  File.swift
//
//
//  Created by iGrant on 24/07/24.
//
import Foundation
import Base58Swift
public enum ValidationError: Error {
    case JWTExpired
    case signatureExpired
    case invalidKID
}
public class CredentialValidatorService: CredentialValidaorProtocol {
    public static var shared = CredentialValidatorService()
    public init() {}
    
    public func validateCredential(jwt: String?, jwksURI: String?, format: String = "") async throws {
        let isJWTExpired = ExpiryValidator().validateExpiryDate(jwt: jwt, format: format) ?? false
        let isSignatureExpied = try await SignatureValidator.validateSign(jwt: jwt, jwksURI: jwksURI, format: format) ?? false
        if isJWTExpired {
            throw ValidationError.JWTExpired
        }
        if !isSignatureExpied {
            throw ValidationError.signatureExpired
        }
    }
    
}
