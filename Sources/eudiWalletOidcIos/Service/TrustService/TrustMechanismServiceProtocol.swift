//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 11/06/25.
//

import Foundation

protocol TrustMechanismServiceProtocol {
    
    func isIssuerOrVerifierTrusted(url: String?, x5c: String?, completion: @escaping (Bool?) -> Void)
    
    func fetchTrustDetails(url: String?, x5c: String?, completion: @escaping (TrustServiceProvider?) -> Void)
}
