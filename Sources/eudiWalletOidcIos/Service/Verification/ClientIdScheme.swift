//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

enum ClientIdScheme: String {
    case redirectURI = "redirect_uri"
    case https = "https"
    case did = "did"
    case verifierAttestation = "verifier_attestation"
    case x509SanDNS = "x509_san_dns"
    case x509SanURI = "x509_san_uri"
    case webOrigin = "web-origin"

    init?(from string: String) {
        self.init(rawValue: string)
    }
}
