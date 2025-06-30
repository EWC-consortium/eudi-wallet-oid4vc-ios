//
//  File.swift
//
//
//  Created by oem on 10/10/24.
//

import Foundation

class ProcessJWKFromJwksUri {
    
    static func processJWKFromJwksURI2(kid: String?, jwksURI: String?) async -> [String: Any] {
        guard let jwksURI = jwksURI else {return [:]}
        return await fetchJwkData(kid: kid, jwksUri: jwksURI)
    }
    
    static func fetchJwkData(kid: String?, jwksUri: String, keyUse: String? = "sig")async -> [String: Any] {
        guard let url = URL(string: jwksUri) else {
            return [:]
        }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else { return [:]}
            guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any], let keys = jsonObject["keys"] as? [[String: Any]] else { return [:]}
            
            var jwkKey: [String: Any]? = keys.first { $0["use"] as? String == keyUse }
            
            if jwkKey == nil, let kid = kid {
                jwkKey = keys.first { $0["kid"] as? String == kid }
            } else {
                jwkKey = keys.first
            }
            return jwkKey ?? [:]
            
        } catch {
            print("error")
        }
        return [:]
    }
}
