//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation
import CryptoKit

class SDJWTVpTokenBuilder : VpTokenBuilder{
    
    
    
    func build(credentials: [String], presentationRequest: PresentationRequest?, did: String, index: Int?, keyHandler: SecureKeyProtocol) async -> String? {
        let item = credentials.first ?? ""
        var claims: [String: Any] = [:]
        claims["aud"] = presentationRequest?.clientId ?? ""
        claims["nonce"] = presentationRequest?.nonce ?? ""
        
        var presentationDefinition :PresentationDefinitionModel? = nil
        do {
            presentationDefinition = try VerificationService.processPresentationDefinition(presentationRequest?.presentationDefinition)
        } catch {
            presentationDefinition = nil
        }
        var transactionData: String? = nil
        if !(presentationRequest?.transactionData?.isEmpty ?? true) {
            transactionData = presentationRequest?.transactionData?.first
            if checkTransactionDataWithMultipleInputDescriptors(inputDescriptor: presentationDefinition?.inputDescriptors?[index ?? 0], transactionDataItem: transactionData) {
                claims["transaction_data_hashes"] = [self.generateHash(input: transactionData ?? "")]
                claims["transaction_data_hashes_alg"] = "sha-256"
            }
        }
        
        var itemWithTilda: String? = nil
        if item.hasSuffix("~") {
            itemWithTilda = item
        } else {
            itemWithTilda = "\(item)~"
        }
        var resultString: String? = nil
            if let keyBindingJwt = await KeyBindingJwtService().generateKeyBindingJwt(issuerSignedJwt: itemWithTilda, claims: claims, keyHandler: keyHandler) {
                var updatedCred = "\(itemWithTilda ?? "")\(keyBindingJwt)"
                resultString = updatedCred
            } else {
                resultString = credentials.first ?? ""
            }
        return resultString
    }
    
    func checkTransactionDataWithMultipleInputDescriptors(inputDescriptor: InputDescriptor?,
                                                          transactionDataItem: String?) -> Bool {
        let decodedTransactionData = transactionDataItem?.decodeBase64() ?? ""
        let transactionDataDict = UIApplicationUtils.shared.convertToDictionary(text: decodedTransactionData)
        let credIdsArray = transactionDataDict?["credential_ids"] as? [String]
        guard let inputDescriptorId = inputDescriptor?.id else { return false }
        return credIdsArray?.contains(inputDescriptorId) ?? false
    }
    
    func generateHash(input: String) -> String? {
        guard let data = input.data(using: .utf8) else { return nil }
        
        let hash = Data(SHA256.hash(data: data))
        
        return hash.map { String(format: "%02x", $0) }.joined()
    }
}
