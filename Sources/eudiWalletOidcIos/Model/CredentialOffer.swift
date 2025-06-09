//
//  CredentialOffer.swift
//
//
//  Created by Mumthasir mohammed on 07/03/24.
//
import Foundation
// MARK: - CredentialOffer model
public struct CredentialOffer {
    public var credentialIssuer: String?
    public var credentials: [Credential]?
    public var grants: Grants?
    public var error: EUDIError?
        public var version: String?
    
    public init(from: CredentialOfferResponse) {
        credentialIssuer = from.credentialIssuer
        
        if let credentialList = from.credentials, credentialList.count > 0{
            if let strCredentialList = credentialList as? [String]{
                credentials = [Credential(fromTypes: strCredentialList)]
            } else if let objCredentialList = credentialList as? [CredentialDataResponse]{
                credentials = credentialList.map({
                    let obj = $0 as! CredentialDataResponse
                    return Credential(from: obj)
                })
            }
        }
        grants = from.grants == nil ? nil : Grants(from: from.grants!)
        grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.txCode = from.grants?.urnIETFParamsOauthGrantTypePreAuthorizedCode?.userPinRequired ?? false ? TransactionCode(length: 4, inputMode: "numeric", description: "") : nil
        grants?.authorizationCode?.authorizationServer = nil
        error = from.error == nil ? nil : EUDIError(from: from.error!)
    version = "v1"
    }
    
    public init(from: CredentialOfferV2) {
        credentialIssuer = from.credentialIssuer
        
        if let credentialList = from.credentialConfigurationIds, credentialList.count > 0{
            if let strCredentialList = credentialList as? [String]{
                credentials = []
                for credential in strCredentialList {
                    credentials?.append(Credential(fromType: credential))
                }
            } else if let objCredentialList = credentialList as? [CredentialDataResponse]{
                credentials = credentialList.map({
                    let obj = $0 as! CredentialDataResponse
                    return Credential(from: obj)
                })
            }
        }
        grants = from.grants == nil ? nil : Grants(from: from.grants!)
        error = from.error == nil ? nil : EUDIError(from: from.error!)
    version = "v2"
    }
    
    public init(fromError: EUDIError) {
        error = fromError
    }
    
}
// MARK: - Credential
public struct Credential {
    public let format: String?
    public let types: [String]?
    public let doctype: String?
    public let trustFramework: TrustFramework?
    public var credentialDefinition: CredentialDefinition?
    
    init(from: CredentialDataResponse) {
        format = from.format
        types = from.types
        doctype = from.doctype
        trustFramework = from.trustFramework == nil ? nil : TrustFramework(from: from.trustFramework!)
        credentialDefinition = from.credentialDefinition == nil ? nil : CredentialDefinition(from: from.credentialDefinition!)
    }
    
    init(fromTypes: [String]) {
        types = fromTypes
        format = nil
        trustFramework = nil
        credentialDefinition = nil
        doctype = nil
    }
    
    init(fromType: String) {
        types = [fromType]
        format = nil
        trustFramework = nil
        credentialDefinition = nil
        doctype = nil
    }
    
}
// MARK: - CredentialDefinition
public struct CredentialDefinition {
    public var context: [String]?
    public var types: [String]?
    
    init(from: CredentialDefinitionResponse) {
        context = from.context
        types = from.types
    }
}
// MARK: - TrustFramework
public struct TrustFramework {
    public let name, type, uri: String?
    
    init(from: TrustFrameworkResponse) {
        name = from.name
        type = from.type
        uri = from.uri
    }
}
public struct Grants {
    public var authorizationCode: AuthorizationCode?
    public var urnIETFParamsOauthGrantTypePreAuthorizedCode: UrnIETFParamsOauthGrantTypePreAuthorizedCode?
    
    init(from: GrantsResponse) {
        authorizationCode = from.authorizationCode == nil ? nil : AuthorizationCode(from: from.authorizationCode!)
        urnIETFParamsOauthGrantTypePreAuthorizedCode = from.urnIETFParamsOauthGrantTypePreAuthorizedCode == nil ? nil : UrnIETFParamsOauthGrantTypePreAuthorizedCode(from: from.urnIETFParamsOauthGrantTypePreAuthorizedCode!)
    }
}
// MARK: - AuthorizationCode
public struct AuthorizationCode  {
    public let issuerState: String?
    public var authorizationServer: String?
    init(from: AuthorizationCodeResponse) {
        issuerState = from.issuerState
        authorizationServer = from.authorizationServer
    }
}
// MARK: - UrnIETFParamsOauthGrantTypePreAuthorizedCode
public struct UrnIETFParamsOauthGrantTypePreAuthorizedCode {
    public let preAuthorizedCode: String?
    public let userPinRequired: Bool?
    public var txCode: TransactionCode?
    public let authorizationServer: String?
    
    init(from: UrnIETFParamsOauthGrantTypePreAuthorizedCodeResponse) {
        preAuthorizedCode = from.preAuthorizedCode
        userPinRequired = from.userPinRequired
        txCode = from.txCode
        authorizationServer = from.authorizationServer
    }
}
