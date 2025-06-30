//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

class VerifierAttestationSchemeHandler: ClientIdSchemeHandler {

    public func validate(presentationRequest: PresentationRequest, jwtRequest: String?) async throws -> Bool? {
        // FIXME: Implement full Verifier Attestation Scheme validation

        guard let jwtRequest = jwtRequest else { return false }

        // Step 1: Decode the outer JWT header
        let segments = jwtRequest.split(separator: ".")
        guard segments.count == 3 else {
            print("Invalid JWT format")
            return false
        }

        let headerSegment = String(segments[0])
        guard let headerJson = headerSegment.decodeBase64(),
              let headerData = headerJson.data(using: .utf8),
              let headerDict = try? JSONSerialization.jsonObject(with: headerData, options: []) as? [String: Any],
              let typ = headerDict["typ"] as? String,
              typ == "verifier-attestation+jwt" else {
            print("Invalid or missing 'typ'")
            return false
        }

        // Step 2: Extract nested Verifier Attestation JWT
        guard let verifierAttestationJWT = headerDict["jwt"] as? String else {
            print("Missing Verifier Attestation 'jwt' field")
            return false
        }

        // Step 3: Decode payload of nested JWT
        let nestedSegments = verifierAttestationJWT.split(separator: ".")
        guard nestedSegments.count == 3 else {
            print("Invalid Verifier Attestation JWT format")
            return false
        }

        let payloadSegment = String(nestedSegments[1])
        guard let payloadJson = payloadSegment.decodeBase64(),
              let payloadData = payloadJson.data(using: .utf8),
              let payloadDict = try? JSONSerialization.jsonObject(with: payloadData, options: []) as? [String: Any] else {
            print("Failed to decode payload")
            return false
        }

        // Step 4: Extract and compare `sub` with clientId
        guard let sub = payloadDict["sub"] as? String else {
            print("Missing 'sub' in Verifier Attestation JWT")
            return false
        }

        let clientId = ClientIdSchemeRequestHandler().getClientIDFromClientID(afterColon: presentationRequest.clientId ?? "" ?? "")

        guard sub == clientId else {
            print("sub and clientId mismatch")
            return false
        }

        // Step 5: Extract cnf → jwk and validate JWT signature (pseudo-code)
        guard let cnf = payloadDict["cnf"] as? [String: Any],
              let jwkDict = cnf["jwk"] as? [String: Any] else {
            print("Missing or invalid cnf.jwk")
            return false
        }

        // ⚠️ Validate `jwtRequest` using the public key from `jwkDict`
       //fixme : validateSignature(jwtRequest: jwtRequest, jwkDict: jwkDict)

        // The Wallet MUST validate the signature on the Verifier attestation JWT. The iss claim value of the Verifier Attestation JWT MUST identify a party the Wallet trusts for issuing Verifier Attestation JWTs. If the Wallet cannot establish trust, it MUST refuse the request. If the issuer of the Verifier Attestation JWT adds a redirect_uris claim to the attestation, the Wallet MUST ensure the redirect_uri request parameter value exactly matches one of the redirect_uris claim entries
//        if let redirectUris = payloadDict["redirect_uris"] as? [String] {
//            guard let actualRedirect = presentationRequest.redirectUri,
//                  redirectUris.contains(actualRedirect) else {
//                print("redirect_uri mismatch")
//                return false
//            }
//        }

        return true
    }
    
    public func update(presentationRequest: PresentationRequest, jwtRequest: String?) -> PresentationRequest {
        var updated = presentationRequest
        
        return updated
    }
}
