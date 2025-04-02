//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//

import Foundation

class ProcessWebJWKFromKID {
    static func fetchDIDDocument(did: String) async throws -> [String: Any]? {
        guard did.hasPrefix("did:web:") else { return nil }
        var publicKeyJwk: [String: Any]? = [:]
        let didWithoutPrefix = did.replacingOccurrences(of: "did:web:", with: "")
        let pathAndFragment = didWithoutPrefix.split(separator: "#").first ?? ""
        let didParts = pathAndFragment.split(separator: ":")
        
        guard didParts.count > 1 else { return nil }
        
        let host = didParts[0]
        let path = didParts.dropFirst().joined(separator: "/")
        var didDocURLString: String = ""
        if path == nil || path == "" {
            didDocURLString = "https://\(host)/.well-known/did.json"
        } else {
            didDocURLString = "https://\(host)/\(path)/did.json"
        }
        
        guard let didDocURL = URL(string: didDocURLString) else { return nil }
        
        let (data, response) = try await URLSession.shared.data(from: didDocURL)
        
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            return nil
        }
        
        let didDoc = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        if let verificationMethod = didDoc?["verificationMethod"] as? [[String: Any]] {
            for (index, item) in verificationMethod.enumerated(){
                if item["id"] as? String == did {
                    publicKeyJwk = verificationMethod[index]["publicKeyJwk"] as? [String: Any]
                }
            }
        }
        return publicKeyJwk
    }
}
