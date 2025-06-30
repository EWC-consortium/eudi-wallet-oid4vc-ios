//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

class RedirectURIHandler: ClientIdSchemeHandler {
    public func validate(presentationRequest: PresentationRequest, jwtRequest: String?) async throws -> Bool? {
        // The Authorization Request MUST NOT be signed, so validation is not needed
        return true
    }

    public func update(presentationRequest: PresentationRequest, jwtRequest: String?) -> PresentationRequest {
        var updated = presentationRequest
        let responseMode = ResponseMode(from: presentationRequest.responseMode ?? "")
        
        let uriToInject = ClientIdSchemeRequestHandler().getClientIDFromClientID(afterColon: presentationRequest.clientId ?? "")
        
        switch responseMode {
        case .directPost, .directPostJWT:
            if updated.responseUri?.isEmpty ?? true {
                updated.responseUri = uriToInject
            }
            
        case .dcApi, .dcApiJWT, .none:
            if updated.redirectUri?.isEmpty ?? true {
                updated.redirectUri = uriToInject
            }
        }
        
        return updated
    }
}
