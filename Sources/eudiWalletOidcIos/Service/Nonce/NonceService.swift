//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 06/06/25.
//

import Foundation

public class NonceService: NonceServiceProtocol {
    
    public static var shared = NonceService()
    public init() {}
    
    public func fetchNonceEndpoint(accessToken: String?, nonceEndPoint: String?) async -> String? {
        guard let url = URL(string: nonceEndPoint ?? "") else { return nil }
        
        var request = URLRequest(url: url)
        request.setValue( "Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        request.httpMethod = "POST"
        
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            let httpRes = response as? HTTPURLResponse
            if httpRes?.statusCode ?? 0 >= 400 {
                return nil
            }
            else {
        guard let jsonObject = try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] else { return nil }
        
                
                return jsonObject["c_nonce"] as? String
            }
        } catch {
            return nil
        }
    }
    
}
