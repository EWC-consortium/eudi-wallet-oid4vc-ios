//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

class X509SanUriSchemeHandler: ClientIdSchemeHandler {
    public func validate(presentationRequest: PresentationRequest, jwtRequest: String?) async throws -> Bool? {
        //fixme: Implement validation logic for X509 SAN DNS scheme
        return true
    }

    public func update(presentationRequest: PresentationRequest, jwtRequest: String?) -> PresentationRequest {
        var updated = presentationRequest
        
        return updated
    }
}
