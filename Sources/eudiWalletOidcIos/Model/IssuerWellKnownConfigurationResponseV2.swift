//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//
import Foundation
public struct IssuerWellKnownConfigurationResponseV2: Codable {
    let credentialIssuer: String?
    let authorizationServer: String?
    let authorizationServers: [String]?
    let credentialEndpoint: String?
    let deferredCredentialEndpoint: String?
    let display: [AnyObject]?
    let credentialsSupported: [AnyObject]?
    public let notificationEndPoint: String?
    
    enum CodingKeys: String, CodingKey {
        case credentialIssuer = "credential_issuer"
        case authorizationServer = "authorization_server"
        case authorizationServers = "authorization_servers"
        case credentialEndpoint =  "credential_endpoint"
        case deferredCredentialEndpoint = "deferred_credential_endpoint"
        case display = "display"
        case credentialsSupported = "credential_configurations_supported"
        case notificationEndPoint = "notification_endpoint"
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
        
        if let singleCredentialSupported = try? container.decode([String:DataSharingResponseV2].self, forKey: .credentialsSupported) {
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
    }
}
