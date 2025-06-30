//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

protocol VpTokenBuilder {
    func build(credentials: [String], presentationRequest: PresentationRequest?, did: String, index: Int?, keyHandler: SecureKeyProtocol) async -> String?
}
