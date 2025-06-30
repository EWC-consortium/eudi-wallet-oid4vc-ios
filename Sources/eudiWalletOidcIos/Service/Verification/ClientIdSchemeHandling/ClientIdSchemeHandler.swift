//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

protocol ClientIdSchemeHandler {
    func validate(presentationRequest: PresentationRequest, jwtRequest: String?) async throws -> Bool?
    func update(presentationRequest: PresentationRequest, jwtRequest: String?) -> PresentationRequest
}
