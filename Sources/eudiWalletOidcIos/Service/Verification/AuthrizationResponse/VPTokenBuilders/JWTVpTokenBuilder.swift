//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

class JWTVpTokenBuilder : VpTokenBuilder{
    
    
    func build(credentials: [String], presentationRequest: PresentationRequest?, did: String, index: Int?, keyHandler: SecureKeyProtocol) async -> String? {
        var jwtPayload: String? = nil
        if !credentials.isEmpty {
            let uuid4 = UUID().uuidString
            let jwtVP =
            ([
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "holder": did,
                "id": "urn:uuid:\(uuid4)",
                "type": [
                    "VerifiablePresentation"
                ],
                "verifiableCredential": credentials
            ] as [String : Any])
            let currentTime = Int(Date().timeIntervalSince1970)
            jwtPayload = ([
                "aud": presentationRequest?.clientId ?? "",
                "exp": currentTime + 3600,
                "iat": currentTime,
                "iss": "\(did)",
                "jti": "urn:uuid:\(uuid4)",
                "nbf": currentTime,
                "nonce": presentationRequest?.nonce ?? "",
                "sub": "\(did)",
                "vp": jwtVP,
            ] as [String : Any]).toString() ?? ""
            
            guard let secureData = keyHandler.generateSecureKey() else { return nil}
            let jwk = generateJWKFromPrivateKey(secureKey: secureData, did: did)
            let header = generateJWTHeader(jwk: jwk, did: did)
            let vpToken = await generateVPToken(header: header, payload: jwtPayload ?? "", keyHandler: keyHandler)
            return vpToken ?? ""
        } else {
            return ""
        }
    }
    
    private func generateJWKFromPrivateKey(secureKey: SecureKeyData, did: String) -> [String: Any] {
        let rawRepresentation = secureKey.publicKey
        let x = rawRepresentation[rawRepresentation.startIndex..<rawRepresentation.index(rawRepresentation.startIndex, offsetBy: 32)]
        let y = rawRepresentation[rawRepresentation.index(rawRepresentation.startIndex, offsetBy: 32)..<rawRepresentation.endIndex]
        return [
            "crv": "P-256",
            "kty": "EC",
            "x": x.urlSafeBase64EncodedString(),
            "y": y.urlSafeBase64EncodedString()
        ]
    }
    
    private func generateJWTHeader(jwk: [String: Any], did: String) -> String {
        let methodSpecificId = did.replacingOccurrences(of: "did:key:", with: "")
        
        return ([
            "alg": "ES256",
            "kid": "\(did)#\(methodSpecificId)",
            "typ": "JWT",
            "jwk": jwk
        ] as [String : Any]).toString() ?? ""
    }
    
    private func generateVPToken(header: String, payload: String, keyHandler: SecureKeyProtocol) async -> String {
        let headerData = Data(header.utf8)
       
        let secureData = await keyHandler.generateSecureKey()
        guard let idToken = keyHandler.sign(payload: payload, header: headerData, withKey: secureData?.privateKey) else{return ""}
       
        return idToken
    }
}
