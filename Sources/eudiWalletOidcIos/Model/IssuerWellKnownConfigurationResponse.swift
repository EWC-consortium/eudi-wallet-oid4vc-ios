//
//  IssuerWellKnownConfigurationResponse.swift
//
//
//  Created by Arun Raj on 07/06/24.
//

import Foundation

// MARK: - IssuerWellKnownConfiguration
public struct DisplayResponse: Codable {
    let name: String?
    let location: String?
    let locale: String?
    let description: String?
    var cover, logo, bgImage: DisplayCoverResponse?
    var backgroundColor, textColor: String?

    enum CodingKeys: String, CodingKey {
        case name = "name"
        case location = "location"
        case locale =  "locale"
        case description = "description"
        case cover = "cover"
        case logo = "logo"
        case bgImage =  "background_image"
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}
struct TrustFrameworkInIssuerResponse: Codable {
    let name: String?
    let type: String?
    let uri: String?
    let display: DisplayResponse?
}
struct CredentialsSupportedResponse: Codable {
    let format: String?
    let types: [String]?
    let trustFramework: TrustFrameworkInIssuerResponse?
    let display: [AnyObject]?
    
    enum CodingKeys: String, CodingKey {
        case format = "format"
        case types = "types"
        case trustFramework =  "trustFramework"
        case display = "display"
    }
    
    public func encode(to encoder: Encoder) throws {
        
    }
    
   init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
       format = try? container.decode(String.self, forKey: .format)
       types = try? container.decode([String].self, forKey: .types)
       trustFramework = try? container.decode(TrustFrameworkInIssuerResponse.self, forKey: .trustFramework)
        if let singleDisplay = try? container.decode(DisplayResponse.self, forKey: .display) {
            display = [singleDisplay] as? [AnyObject]
        } else if let displayArray = try? container.decode([DisplayResponse].self, forKey: .display) {
            display = displayArray as? [AnyObject]
        } else {
            throw DecodingError.dataCorruptedError(forKey: .display, in: container, debugDescription: "Display value is missing or invalid.")
        }
    }
}

// MARK: - CredentialsSupportedObject
struct CredentialsSupportedObjectTypeResponse: Codable {
    var credentialsSupported: CredentialSupportedObjectResponse?

    enum CodingKeys: String, CodingKey {
        case credentialsSupported = "credentials_supported"
    }
}

// MARK: - CredentialObj
struct CredentialSupportedObjectResponse : Codable {
    //var portableDocumentA1, parkingTicket, testDraft2, dataSharing: DataSharingResponse?
    var credentialsSupported: [String: DataSharingResponse]?
    var format: String?
    var types: [String]?
    var trustFramework: TrustFrameworkResponse?
    var display: [DisplayElementResponse]?
    
    enum CodingKeys: String, CodingKey {
        case credentialsSupported = "credentials_supported"
    }

}

struct DisplayElementResponse: Codable {
    var name: String?
    var locale: Locale?
}

enum FormatResponse: String, Codable {
    case jwtVc = "jwt_vc"
}

// MARK: - DataSharing
struct DataSharingResponse: Codable {
    var format, scope: String?
    var cryptographicBindingMethodsSupported, cryptographicSuitesSupported: [String]?
    var display: [DisplayResponse]?
    var credentialDefinition: IssuerCredentialDefinitionResponse?
    var docType: String?
    
    enum CodingKeys: String, CodingKey {
        case format, scope
        case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
        case cryptographicSuitesSupported = "cryptographic_suites_supported"
        case display
        case credentialDefinition = "credential_definition"
    case docType = "doctype"
    }
}

struct DataSharingOldFormatResponse: Codable {
    var format: String?
    var types: [String]?
    var trustFramework: TrustFrameworkResponse?
    var display: [DisplayResponse]?
    var docType: String?
    
    enum CodingKeys: String, CodingKey {
        case format, types
        case trustFramework = "trust_framework"
        case display
        case docType = "doctype"
    }
}


struct DataSharingResponseV2: Codable {
    var format, scope: String?
    var cryptographicBindingMethodsSupported, cryptographicSuitesSupported: [String]?
    var display: [DisplayResponse]?
    var credentialDefinition: IssuerCredentialDefinitionResponse?
    var vct: String?
        var docType: String?
    
    enum CodingKeys: String, CodingKey {
        case format, scope, vct
        case cryptographicBindingMethodsSupported = "cryptographic_binding_methods_supported"
        case cryptographicSuitesSupported = "credential_signing_alg_values_supported"
    case credentialDefinition = "credential_definition"
        case display
        case docType = "doctype"
    }
}

// MARK: - DataSharingDisplay
struct DataSharingDisplayResponse: Codable {
    var name, locale, backgroundColor, textColor: String?

    enum CodingKeys: String, CodingKey {
        case name, locale
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}

// MARK: - CredentialsSupportedObjectDisplay
struct CredentialsSupportedObjectDisplayResponse: Codable {
    var name, location, locale: String?
    var cover, logo: DisplayCoverResponse?
    var description: String?
}

//MARK: Credential Definition
struct IssuerCredentialDefinitionResponse: Codable {
    var type: [String]?
    var vct: String?
}

// MARK: - Cover
struct DisplayCoverResponse: Codable {
    var url: String?
    var uri: String?
    var altText: String?

    enum CodingKeys: String, CodingKey {
        case url
        case uri
        case altText = "alt_text"
    }
}


public struct IssuerWellKnownConfigurationResponse: Codable {
    let credentialIssuer: String?
    let authorizationServer: String?
    let authorizationServers: [String]?
    let credentialEndpoint: String?
    let deferredCredentialEndpoint: String?
    let display: [AnyObject]?
    let credentialsSupported: [AnyObject]?
    public let notificationEndPoint: String?
    let nonceEndpoint: String?
    
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case authorizationServer = "authorization_server"
        case authorizationServers = "authorization_servers"
        case credentialEndpoint =  "credential_endpoint"
        case deferredCredentialEndpoint = "deferred_credential_endpoint"
        case display = "display"
        case credentialsSupported = "credentials_supported"
        case notificationEndPoint = "notification_endpoint"
        case nonsceEndpoint = "nonce_endpoint"
    }
    
    public func encode(to encoder: Encoder) throws {
        
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        credentialIssuer = try? container.decode(String.self, forKey: .credentialIssuer)
        authorizationServer = try? container.decode(String.self, forKey: .authorizationServer)
        authorizationServers = try? container.decode([String].self, forKey: .authorizationServers)
        credentialEndpoint = try? container.decode(String.self, forKey: .credentialEndpoint)
        deferredCredentialEndpoint = try? container.decode(String.self, forKey: .deferredCredentialEndpoint)
        
        if let singleCredentialSupported = try? container.decode([String:DataSharingResponse].self, forKey: .credentialsSupported) {
            credentialsSupported = [singleCredentialSupported] as? [AnyObject]
        } else if let credentialSupportedArray = try? container.decode([DataSharingOldFormatResponse].self, forKey: .credentialsSupported) {
            credentialsSupported = credentialSupportedArray as? [AnyObject]
        } else {
            credentialsSupported = []
        }
        
        if let singleDisplay = try? container.decode(DisplayResponse.self, forKey: .display) {
            display = [singleDisplay] as? [AnyObject]
        } else if let displayArray = try? container.decode([DisplayResponse].self, forKey: .display) {
            display = displayArray as? [AnyObject]
        } else {
            display = []
        }
        notificationEndPoint = try? container.decode(String.self, forKey: .notificationEndPoint)
        nonceEndpoint = try? container.decode(String.self, forKey: .nonsceEndpoint)
    }
}
