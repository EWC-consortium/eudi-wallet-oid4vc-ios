//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//
import Foundation
public struct CredentialResponseV2: Codable {
    public var format, credential, acceptanceToken: String?
    public var isDeferred, isPinRequired: Bool?
    public var issuerConfig: IssuerWellKnownConfiguration?
    public var authorizationConfig: AuthorisationServerWellKnownConfiguration?
    public var credentialOffer: CredentialOffer?
    public var error: EUDIError?
    public var notificationID: String?
    public var credentials: [CredentialItem]?
    
    enum CodingKeys: String, CodingKey {
        case acceptanceToken = "transaction_id"
        case format = "format"
        case credential = "credential"
        case notificationID = "notification_id"
        case credentials = "credentials"
    }
}
