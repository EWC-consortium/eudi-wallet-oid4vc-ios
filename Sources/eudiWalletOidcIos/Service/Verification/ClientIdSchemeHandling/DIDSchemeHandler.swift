//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

class DIDSchemeHandler: ClientIdSchemeHandler {
    public func validate(presentationRequest: PresentationRequest, jwtRequest: String?) async throws -> Bool? {
        let isVerified = try await SignatureValidator.validateSign(jwt: jwtRequest, jwksURI: nil, format: "") ?? false
        return isVerified
    }

    public func update(presentationRequest: PresentationRequest, jwtRequest: String?) -> PresentationRequest {
        var updated = presentationRequest
        
        return updated
    }
}
