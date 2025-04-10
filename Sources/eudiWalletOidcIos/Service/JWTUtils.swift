//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 09/04/25.
//

import Foundation

class JWTUtils {
    
    func isValidJwt(_ jwt: String) -> Bool {
        return jwt.contains(".")
    }
    
}
