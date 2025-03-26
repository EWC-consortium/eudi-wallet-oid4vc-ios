//
//  CredentialResponse.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//
import Foundation
// MARK: - CredentialResponse
public struct CredentialResponse {
    public var format, credential, acceptanceToken: String?
    public var isDeferred, isPinRequired: Bool?
    public var issuerConfig: IssuerWellKnownConfiguration?
    public var authorizationConfig: AuthorisationServerWellKnownConfiguration?
    public var credentialOffer: CredentialOffer?
    public var error: EUDIError?
    public var notificationID: String?
    
    
    public init(from: CredentialResponseV1) {
        format = from.format
        credential = from.credential
        acceptanceToken = from.acceptanceToken
        isDeferred = from.isDeferred
        isPinRequired = from.isPinRequired
        issuerConfig = from.issuerConfig
        authorizationConfig = from.authorizationConfig
        credentialOffer = from.credentialOffer
        error = from.error
        notificationID = from.notificationID
    }
    
    
    public init(from: CredentialResponseV2) {
        format = from.format
        credential = from.credential
        acceptanceToken = from.acceptanceToken
        isDeferred = from.isDeferred
        isPinRequired = from.isPinRequired
        issuerConfig = from.issuerConfig
        authorizationConfig = from.authorizationConfig
        credentialOffer = from.credentialOffer
        error = from.error
        notificationID = from.notificationID
    }
    
    public init(fromError: EUDIError) {
        error = fromError
    }
}
