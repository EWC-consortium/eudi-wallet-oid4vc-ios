//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//

import Foundation

class ProcessEbsiJWKFromKID {
    
    static func processJWKforEBSI(kid: String?) async -> [String: Any] {
        guard let kid = kid else { return [:] }
        
        // Extract did from kid
        let did: String
        if let firstPart = kid.split(separator: "#").first {
            did = String(firstPart)
        } else {
            did = kid // Fallback to the original kid
        }
        
        let ebsiEndPoint = "https://api-conformance.ebsi.eu/did-registry/v5/identifiers/\(did)"
        let pilotEndpoint = "https://api-pilot.ebsi.eu/did-registry/v5/identifiers/\(did)"
        
        // Try fetching from primary endpoint
        if let publicKeyJwk = await fetchAndProcessJWK(from: ebsiEndPoint, kid: kid) {
            return publicKeyJwk
        }
        
        // Try fetching from pilot endpoint if not found in primary
        if let publicKeyJwk = await fetchAndProcessJWK(from: pilotEndpoint, kid: kid) {
            return publicKeyJwk
        }
        
        // Return empty if not found in both
        return [:]
    }
    
    private static func fetchAndProcessJWK(from urlString: String, kid: String) async -> [String: Any]? {
        guard let url = URL(string: urlString) else { return nil }
        
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else { return nil }
            
            return try processPublicKeyFromJWKList(data, kid: kid)
        } catch {
            print("Error fetching from \(urlString): \(error)")
            return nil
        }
    }
    
    private static func processPublicKeyFromJWKList(_ data: Data, kid: String) throws -> [String: Any]? {
        guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
              let verificationMethods = jsonObject["verificationMethod"] as? [[String: Any]] else { return nil }
        
        for method in verificationMethods {
            if let methodID = method["id"] as? String, methodID == kid,  // New condition: Match "id" with kid
               let publicKeyJwk = method["publicKeyJwk"] as? [String: Any],
               let crv = publicKeyJwk["crv"] as? String, crv == "P-256" {
                return publicKeyJwk
            }
        }
        return nil
    }
}
