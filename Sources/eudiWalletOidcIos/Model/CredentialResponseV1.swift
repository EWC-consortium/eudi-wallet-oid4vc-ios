//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//
import Foundation
public struct CredentialResponseV1: Codable {
    public var format, credential, acceptanceToken: String?
    public var isDeferred, isPinRequired: Bool?
    public var issuerConfig: IssuerWellKnownConfiguration?
    public var authorizationConfig: AuthorisationServerWellKnownConfiguration?
    public var credentialOffer: CredentialOffer?
    public var error: EUDIError?
    public var notificationID: String?
    
    enum CodingKeys: String, CodingKey {
        case acceptanceToken = "acceptance_token"
        case format = "format"
        case credential = "credential"
        case notificationID = "notification_id"
    }
}
