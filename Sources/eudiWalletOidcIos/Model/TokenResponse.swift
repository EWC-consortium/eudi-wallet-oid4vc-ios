//
//  TokenResponse.swift
//
//
//  Created by Mumthasir mohammed on 11/03/24.
//
import Foundation
// MARK: - TokenResponse (getAccessToken() Api call response model))
public struct TokenResponse: Codable {
    public var accessToken: String?
    public var tokenType: String?
    public var expiresIn: Int?
    public var idToken: String?
    public var cNonce: String?
    public var cNonceExpiresIn: Int?
    public var scope: String?
    public var error: EUDIError? // Optional error property
    public var refreshToken: String?
    public var lpid: String?
    public var lpidPop: String?
    public var authorizationDetails: [AuthorizationDetails]?
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case idToken = "id_token"
        case cNonce = "c_nonce"
        case cNonceExpiresIn = "c_nonce_expires_in"
        case scope = "scope"
        case refreshToken = "refresh_token"
        case authorizationDetails = "authorization_details"
    }
    
    
    // Initializer to handle the case when an error occurs
//    init(error: error) {
//        self.error = error
//        // Other properties will be nil by default
//    }
}

public struct AuthorizationDetails : Codable {
    public var type: String?
    public var credentialConfigId: String?
    public var credentialIdentifiers: [String]?
    
    enum CodingKeys: String, CodingKey {
        case type = "type"
        case credentialConfigId = "credential_configuration_id"
        case credentialIdentifiers = "credential_identifiers"
    }
}
