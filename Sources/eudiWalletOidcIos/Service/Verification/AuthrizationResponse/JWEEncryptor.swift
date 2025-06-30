//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation
import JOSESwift
import CryptoKit

class JWEEncryptor {

    func encrypt(
        payload: [String: Any],
        presentationRequest: PresentationRequest?
    ) async throws -> String {
        // 1. Get P-256 public key from `jwks` or `jwks_uri`
        let jwk: [String: Any]
        var clientMetaData: [String: Any] = [:]
        if let clientMetaDataString = presentationRequest?.clientMetaData, let dataObject = clientMetaDataString.data(using: .utf8) {
            do {
                let dict = try JSONSerialization.jsonObject(with: dataObject, options: []) as? [String: Any]
                clientMetaData = dict ?? [:]
            } catch {
                print("")
            }
        }

        if let jwksURI = clientMetaData["jwks_uri"] as? String {
            jwk = try await fetchJWKFromURI(jwksURI)
        } else if let jwks = clientMetaData["jwks"] as? [String: Any],
                  let keys = jwks["keys"] as? [[String: Any]],
                  let p256Key = keys.first(where: { $0["crv"] as? String == "P-256" }) {
            jwk = p256Key
        } else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "No P-256 key found"])
        }

        guard let x = jwk["x"] as? String,
              let y = jwk["y"] as? String,
              let kid = jwk["kid"] as? String else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "Invalid JWK"])
        }

        // 2. Build public EC key (JWK)
        //let ecKey = try EphemeralPublicKey(x: x, y: y)
        
        let ecKeyData = ECPublicKey(crv: .P256, x: x, y: y, additionalParameters: ["kid": kid])
        
        let ecKeyjwk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "kid": kid
        ]

        // 3. JWE Header with ECDH-ES + A128CBC-HS256
        var header = JWEHeader(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A128CBCHS256)
        header.kid = kid
        //header["apu"] = presentationRequest?.clientId?.data(using: .utf8)
        // set header key apu and value presentationRequest.clientId?.data(using: .utf8)
            // set apv presentationRequest.nonce?.data(using: .utf8)
        let apuData = presentationRequest?.clientId?.data(using: .utf8)
        let apvData = presentationRequest?.nonce?.data(using: .utf8)
        header.apu = apuData?.base64URLEncodedString()
        header.apv = apvData?.base64URLEncodedString()
//        header.agreementPartyUInfo = presentationRequest.clientId?.data(using: .utf8)
//        header.agreementPartyVInfo = presentationRequest.nonce?.data(using: .utf8)

        // 4. Convert payload to JSON data
        let payloadData = try JSONSerialization.data(withJSONObject: payload, options: [])

        // 5. Encrypt
        let payloadEncrypted = Payload(payloadData)
        let encrypter = try Encrypter(keyManagementAlgorithm: .ECDH_ES, contentEncryptionAlgorithm: .A128CBCHS256, encryptionKey: ecKeyData)
//        ECDHEncrypter(keyEncryptionAlgorithm: .ECDH_ES,
//                                          encryptionAlgorithm: .A128CBCHS256,
//                                          recipientPublicKey: ecKey)
        guard let encrypter = encrypter else { return ""}
        let jwe = try JWE(header: header, payload: payloadEncrypted, encrypter: encrypter)

        return jwe.compactSerializedString
    }
    
    func base64UrlDecode(_ str: String) -> Data? {
        var base64 = str
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        let paddingLength = 4 - base64.count % 4
        if paddingLength < 4 {
            base64 += String(repeating: "=", count: paddingLength)
        }
        return Data(base64Encoded: base64)
    }
    
    func ecPublicKeyWithoutKid(x: String, y: String) throws -> SecKey {
        guard
            let xData = base64UrlDecode(x),
            let yData = base64UrlDecode(y)
        else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "Invalid base64url x/y"])
        }

        // P-256 uncompressed key = 0x04 + x + y
        var keyBytes = Data([0x04])
        keyBytes.append(xData)
        keyBytes.append(yData)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]

        guard let secKey = SecKeyCreateWithData(keyBytes as CFData, attributes as CFDictionary, nil) else {
            throw NSError(domain: "JWE", code: 400, userInfo: [NSLocalizedDescriptionKey: "Failed to create EC key"])
        }

        return secKey
    }

    // Helper: Convert base64url strings to EC public key (CryptoKit)
    struct EphemeralPublicKey {
        let x: String
        let y: String

        var rawRepresentation: Data {
            let xData = Data(base64URLEncoded: x)!
            let yData = Data(base64URLEncoded: y)!
            return Data([0x04]) + xData + yData // Uncompressed EC point format
        }

        init(x: String, y: String) throws {
            self.x = x
            self.y = y
        }
    }

    // Helper: Fetch JWK from URI (you need to implement async network fetch)
    private func fetchJWKFromURI(_ uri: String) async -> [String: Any] {
        return await ProcessJWKFromJwksUri.fetchJwkData(kid: nil, jwksUri: uri, keyUse: "enc")
    }
}
