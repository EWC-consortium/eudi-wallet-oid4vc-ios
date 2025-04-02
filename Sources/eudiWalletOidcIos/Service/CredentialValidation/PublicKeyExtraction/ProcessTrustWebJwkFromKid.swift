//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 31/03/25.
//

import Foundation

class ProcessTrustWebJwkFromKid {
    
    static func fetchDIDDocument(did: String) async throws -> [String: Any]? {
        guard did.hasPrefix("did:tdw:") else { return nil }
        var publicKeyJwk: [String: Any]? = [:]
        let didWithoutPrefix = did.replacingOccurrences(of: "did:tdw:", with: "")

        let scidComponents = didWithoutPrefix.components(separatedBy: ":")
            guard scidComponents.count > 1 else {
                return nil
        }
        let afterScid = scidComponents.dropFirst().joined(separator: ":")
        let pathComponents = afterScid.replacingOccurrences(of: ":", with: "/")
        let path = pathComponents.split(separator: "#").first ?? ""
        let decodedPath = path.removingPercentEncoding
        let pathsParts = decodedPath?.components(separatedBy: "/")
        var decodedString: String = ""
        let host = pathsParts?[0]
        let pathItem = pathsParts?.dropFirst().joined(separator: "/")
        
        if pathItem == nil || pathItem == "" {
            decodedString = "\(host ?? "")/.well-known"
        } else {
            decodedString = "\(host ?? "")/\(pathItem ?? "")"
        }
        var url = "https://\(decodedString)/did.jsonl"
        
        guard let didDocURL = URL(string: url) else { return nil }
        
        let (data, response) = try await URLSession.shared.data(from: didDocURL)
        
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            return nil
        }
        
        let didDoc = try JSONSerialization.jsonObject(with: data, options: []) as? [Any]
        
        guard let valueDict = didDoc?.first(where: { element in
            if let dict = element as? [String: Any] {
                return dict["value"] != nil
            }
            return false
        }) as? [String: Any] else {  return nil}
        
        if let innerValue = valueDict["value"] as? [String: Any],
           let verificationMethods = innerValue["verificationMethod"] as? [[String: Any]]  {
            for (index, data) in verificationMethods.enumerated() {
                if let id = data["id"] as? String {
                    if id == did {
                        publicKeyJwk = verificationMethods[index]["publicKeyJwk"] as? [String: Any]
                    }
                }
            }
        }
        return publicKeyJwk
    }
    
}
