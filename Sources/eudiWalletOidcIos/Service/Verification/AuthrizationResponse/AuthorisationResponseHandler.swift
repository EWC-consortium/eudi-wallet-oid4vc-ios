//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation

class AuthorisationResponseHandler {
    
    func prepareAuthorisationResponse(credentialsList: [String]?,
                                      presentationRequest: PresentationRequest?,
                                      did: String, keyHandler: SecureKeyProtocol) async -> [String: Any]?{
        guard let responseMode = ResponseMode(from: presentationRequest?.responseMode ?? "") else { return nil}
        switch responseMode {
        case .directPost:
            return await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler)
        case .directPostJWT:
            let params = await AuthorisationResponseBuilder.buildResponse(credentialsList: credentialsList, presentationRequest: presentationRequest, did: did, keyHandler: keyHandler)
            do {
                let encrypted = try await JWEEncryptor().encrypt(payload: params, presentationRequest: presentationRequest)
                var encryptedResponseParams: [String: Any] = [:]
                encryptedResponseParams["response"] = encrypted
                return encryptedResponseParams
            } catch {
                return nil
                print("")
            }
        case .dcApi:
            print("Handling DC API response mode")
            return [:]
        case .dcApiJWT:
            print("Handling DC API JWT response mode")
            return [:]
        default:
            print("Handling default response mode")
            return [:]
        }
    }
}
