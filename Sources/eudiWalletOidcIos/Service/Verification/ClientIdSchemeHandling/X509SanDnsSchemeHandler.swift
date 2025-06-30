//
//  Untitled.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

class X509SanDnsSchemeHandler: ClientIdSchemeHandler {
    
    /// Validates the x509_san based presentation request using the provided JWT.
    /// Performs 3 validations:
    /// 1. Checks if the client ID matches the SAN in the x5c certificate.
    /// 2. Validates the certificate trust chain.
    /// 3. Verifies the JWT signature using the x5c certificate.
    ///
    /// - Parameters:
    ///   - presentationRequest: The request containing the client ID.
    ///   - jwtRequest: The JWT as a string, which may be nil.
    /// - Returns: A boolean indicating whether all validations passed.
    /// - Throws: Rethrows any exceptions from underlying validators.
    public func validate(presentationRequest: PresentationRequest, jwtRequest: String?) async throws -> Bool? {
        // Extract x5c certificate chain from the JWT
        let x5cData = X509SanRequestVerifier.shared.extractX5cFromJWT(jwt: jwtRequest ?? "") ?? []

        // Extract the client ID suffix (after colon) and validate against x5c SAN
        let clientID = ClientIdSchemeRequestHandler().getClientIDFromClientID(afterColon: presentationRequest.clientId ?? "") ?? ""
        let isClientIDvalid = X509SanRequestVerifier.shared.validateClientIDInCertificate(
            x5cChain: x5cData,
            clientID: clientID
        )

        // Validate the certificate trust chain
        let isTrustChainValid = X509SanRequestVerifier.shared.validateTrustChain(x5cChain: x5cData)

        // Validate the JWT's signature using the x5c certificate
        let isSignValid = X509SanRequestVerifier.shared.validateSignatureWithCertificate(
            jwt: jwtRequest ?? "",
            x5cChain: x5cData
        )

        // Return true only if all validations pass
        if isClientIDvalid && isTrustChainValid && isSignValid {
            return true
        } else {
            return false
        }
    }
    
    public func update(presentationRequest: PresentationRequest, jwtRequest: String?) -> PresentationRequest {
        var updated = presentationRequest
        
        return updated
    }
}
