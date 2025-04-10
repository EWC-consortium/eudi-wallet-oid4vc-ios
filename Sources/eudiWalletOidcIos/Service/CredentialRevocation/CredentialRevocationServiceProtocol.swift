//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 09/04/25.
//

import Foundation


protocol CredentialRevocationServiceProtocol {
    
    func getRevokedCredentials(credentialList: [String], keyHandler: SecureKeyProtocol) async -> [String]
    func getStatusDetailsFromStatusList(jwt: String?, keyHandler: SecureKeyProtocol) -> (String?, Int?)
    func fetchStatusModel(statusList: [String?]) async -> [StatusListModel]
    
}
