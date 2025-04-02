//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 02/04/25.
//

import Foundation

class ProofService {
    
    static func generateProof(nonce: String, credentialOffer: CredentialOffer, issuerConfig: IssuerWellKnownConfiguration, did: String, keyHandler: SecureKeyProtocol) async -> String? {
        let keyId = generateKeyId(credentialOffer: credentialOffer, issuerConfig: issuerConfig, did: did, keyHandler: keyHandler)
        // Generate JWT Header
        let header = ([
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "kid": keyId
        ]).toString() ?? ""
        
        // Generate JWT payload
        let currentTime = Int(Date().epochTime) ?? 0
        let payload = ([
            "iss": did,
            "iat": currentTime,
            "aud": "\(credentialOffer.credentialIssuer ?? "")",
            "exp": currentTime + 86400,
            "nonce": "\(nonce)"
        ] as [String : Any]).toString() ?? ""
        let headerData = Data(header.utf8)
        let secureData = await keyHandler.generateSecureKey()
        guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else{return nil}
        return idToken
    }
    
    static func generateKeyId(credentialOffer: CredentialOffer,
                                issuerConfig: IssuerWellKnownConfiguration, did: String, keyHandler: SecureKeyProtocol) -> String? {
        let cryptographicBindingMethodsSupported = getCryptographicBindingMethodsFromIssuerConfig(issuerConfig: issuerConfig, type: credentialOffer.credentials?.first?.types?.last)
        var keyId: String? = nil
        let methodSpecificId = did.replacingOccurrences(of: "did:key:", with: "")
        if cryptographicBindingMethodsSupported.contains("did:jwk") {
            guard let jwk = keyHandler.getJWK(publicKey: keyHandler.generateSecureKey()?.publicKey ?? Data()) else { return nil }
            let base64JWK = base64URLEncodeJWK(jwk) ?? ""
            keyId = "did:jwk:\(base64JWK)"
        } else {
            keyId = "\(did)#\(methodSpecificId)"
        }
        return keyId
    }
    
    static func getCryptographicBindingMethodsFromIssuerConfig(issuerConfig: IssuerWellKnownConfiguration?, type: String?) -> [String] {
        guard let issuerConfig = issuerConfig else { return [] }
        
        if let credentialSupported = issuerConfig.credentialsSupported?.dataSharing?[type ?? ""] {
            return credentialSupported.cryptographicBindingMethodsSupported ?? []
        } else {
            return []
        }
    }
    
    static func base64URLEncodeJWK(_ jwk: [String: Any]) -> String? {
        guard let jsonData = try? JSONSerialization.data(withJSONObject: jwk, options: []) else {
            return nil
        }
        
        let base64String = jsonData.base64EncodedString()
        
        let base64URLString = base64String
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        
        return base64URLString
    }
    
}
