//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

enum ResponseMode: String {
    case directPost = "direct_post"
    case directPostJWT = "direct_post.jwt"
    case dcApi = "dc_api"
    case dcApiJWT = "dc_api.jwt"

    init?(from string: String) {
        self.init(rawValue: string)
    }
}
