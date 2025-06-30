//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 17/06/25.
//

import Foundation

enum PresentationRequestError: Error {
    case requestValidationFailed
}

class ClientIdSchemeRequestHandler {
    func handle(jwtRequest: String?, presentationRequest: PresentationRequest) async throws -> PresentationRequest? {
        guard let scheme = ClientIdScheme(from: presentationRequest.clientIDScheme ?? "") else { return nil }
        switch scheme {
        case .redirectURI:
            return RedirectURIHandler().update(presentationRequest: presentationRequest, jwtRequest: jwtRequest)
        case .did:
                let isVerified = try await DIDSchemeHandler().validate(presentationRequest: presentationRequest, jwtRequest: jwtRequest) ?? false
                if isVerified {
                    return presentationRequest
                } else {
                    // Handle verification failure
                    // Fix me - throw error - request validation failed
                    return presentationRequest
                    //throw PresentationRequestError.requestValidationFailed// or throw an error
                }
        case .verifierAttestation:
                let isVerified = try await VerifierAttestationSchemeHandler().validate(presentationRequest: presentationRequest, jwtRequest: jwtRequest) ?? false
                if isVerified {
                    return presentationRequest
                } else {
                    // Handle verification failure
                    // Fix me - throw error
                    return presentationRequest
                    //throw PresentationRequestError.requestValidationFailed// or throw an error
                }
            
        case .x509SanDNS:
                let isVerified = try await X509SanDnsSchemeHandler().validate(presentationRequest: presentationRequest, jwtRequest: jwtRequest) ?? false
                if isVerified {
                    return presentationRequest
                } else {
                    return presentationRequest
                    // Fix me - throw error
                    // Handle verification failure
                    //throw PresentationRequestError.requestValidationFailed// or throw an error
                }
        case .x509SanURI:
                let isVerified = try await X509SanUriSchemeHandler().validate(presentationRequest: presentationRequest, jwtRequest: jwtRequest) ?? false
                if isVerified {
                    return presentationRequest
                } else {
                    // Fix me - throw error
                    // Handle verification failure
                    throw PresentationRequestError.requestValidationFailed// or throw an error
                }
        case .webOrigin:
            return presentationRequest
        default:
            return presentationRequest
        }
    }
    
    public func getClientIDSchemeFromClientID(beforeColon input: String) -> String {
        guard input.contains(":") else { return ""}
        return input.components(separatedBy: ":").first ?? ""
    }
    
    public func getClientIDFromClientID(afterColon input: String) -> String {
        guard let range = input.range(of: ":") else {
            return ""
        }
        return String(input[range.upperBound...])
    }
}
