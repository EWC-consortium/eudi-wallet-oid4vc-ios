//
//  File.swift
//
//
//  Created by Arun Raj on 05/06/24.
//

import Foundation

// MARK: - CredentialOffer model
public struct CredentialOfferResponse: Codable {
    var credentialIssuer: String?
    var credentials: [AnyObject]?
    var grants: GrantsResponse?
    var error: ErrorResponse?
    
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case credentials, grants, error
    }

    
    public func encode(to encoder: Encoder) throws {
        
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.credentialIssuer = try container.decodeIfPresent(String.self, forKey: .credentialIssuer)
        if let stringArray = try? container.decode([String].self, forKey: .credentials) {
            credentials = stringArray as? [AnyObject]
        } else if let credentialArray = try? container.decode([CredentialDataResponse].self, forKey: .credentials) {
            credentials = credentialArray as? [AnyObject]
        } else {
            credentials = nil
        }
        self.grants = try container.decodeIfPresent(GrantsResponse.self, forKey: .grants)
        self.error = try container.decodeIfPresent(ErrorResponse.self, forKey: .error)
    }

}

// MARK: - Credential
struct CredentialDataResponse: Codable {
    let format: String?
    let types: [String]?
    let doctype: String?
    let trustFramework: TrustFrameworkResponse?
    var credentialDefinition: CredentialDefinitionResponse?
    
    enum CodingKeys: String, CodingKey {
        case format, types
        case trustFramework = "trust_framework"
        case credentialDefinition
        case doctype
    }
}


struct CredentialStringResponse{
    
}


// MARK: - CredentialDefinition
struct CredentialDefinitionResponse: Codable {
    var context: [String]?
    var types: [String]?

    enum CodingKeys: String, CodingKey {
        case context
        case types
    }
}

// MARK: - TrustFramework
struct TrustFrameworkResponse: Codable {
    let name, type, uri: String?
}

// MARK: - Grants
struct GrantsResponse: Codable {
    let authorizationCode: AuthorizationCodeResponse?
    let urnIETFParamsOauthGrantTypePreAuthorizedCode: UrnIETFParamsOauthGrantTypePreAuthorizedCodeResponse?

    enum CodingKeys: String, CodingKey {
        case authorizationCode = "authorization_code"
        case urnIETFParamsOauthGrantTypePreAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    }
}

// MARK: - AuthorizationCode
struct AuthorizationCodeResponse: Codable {
    let issuerState: String?
    let authorizationServer: String?
    
    enum CodingKeys: String, CodingKey {
        case issuerState = "issuer_state"
        case authorizationServer = "authorization_server"
    }
}

// MARK: - UrnIETFParamsOauthGrantTypePreAuthorizedCode
struct UrnIETFParamsOauthGrantTypePreAuthorizedCodeResponse: Codable {
    let preAuthorizedCode: String?
    let userPinRequired: Bool?
    let txCode: TransactionCode?
    let authorizationServer: String?
    
    enum CodingKeys: String, CodingKey {
        case preAuthorizedCode = "pre-authorized_code"
        case userPinRequired = "user_pin_required"
        case txCode = "tx_code"
        case authorizationServer = "authorization_server"
    }
}

