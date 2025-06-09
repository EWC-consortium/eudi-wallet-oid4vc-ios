//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 06/06/25.
//

import Foundation

protocol NonceServiceProtocol {
    func fetchNonceEndpoint(accessToken: String?, nonceEndPoint: String?) async -> String
}
