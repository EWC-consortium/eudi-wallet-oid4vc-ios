//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 11/06/25.
//

import Foundation

public class TrustMechanismService: TrustMechanismServiceProtocol {
    
    public static var shared = TrustMechanismService()
    public init() {}
    
    public func isIssuerOrVerifierTrusted(url: String?, x5c: String?, completion: @escaping (Bool?) -> Void){
        var isValidOrganization: Bool? = nil
        var validationResults: [Bool?] = []
        parseXmlDataToJson(url: url) { data in
            if let data = data {
                for item in data.trustServiceProviders ?? [] {
                    for service in item.tspServices {
                        if let identities = service.serviceDigitalIdentities {
                            for identity in identities {
                                if identity.x509Certificate == x5c {
                                    validationResults.append(true)
                                
                                } else if identity.x509SKI == x5c {
                                    validationResults.append(true)
                                }
                            }
                        }
                    }
                }
                if validationResults.contains(true) {
                    completion(true)
                } else {
                    completion(nil)
                }
            } else {
                completion(nil)
            }
            
        }
    }

public func fetchTrustDetails(url: String?, x5c: String?, completion: @escaping (TrustServiceProvider?) -> Void) {
    parseXmlDataToJson(url: url) { data in
        guard let data = data else {
            completion(nil)
            return
        }

        for item in data.trustServiceProviders ?? [] {
            for service in item.tspServices {
                let hasMatchingId = service.serviceDigitalIdentities?.contains {
                    $0.x509Certificate == x5c || $0.x509SKI == x5c
                } ?? false

                if hasMatchingId {
                    var matchedTSP = item
                    matchedTSP.tspServices = [service]
                    completion(matchedTSP)
                    return
                }
            }
        }

        completion(nil)
    }
}
    
    public func parseXmlDataToJson(url: String?, completion: @escaping (TrustServiceStatusList?) -> Void) {
        let url = URL(string: "https://ewc-consortium.github.io/ewc-trust-list/EWC-TL")!
                URLSession.shared.dataTask(with: url) { data, response, error in
                    guard let data = data, error == nil else {
                        print("Error fetching XML: \(error?.localizedDescription ?? "Unknown error")")
                        return
                    }
                    
                    let parser = XMLToJSONParser()
                        parser.parse(xmlData: data) { result in
                            switch result {
                            case .success(let jsonData):
                                if let jsonString = String(data: jsonData, encoding: .utf8) {
                                    print("JSON Output:")
                                    print(jsonString)
                                    
                                    
                                    
                                    do {
                                        if let jsonData = jsonString.data(using: .utf8) {
                                            let decoder = JSONDecoder()
                                            let trustServiceList = try decoder.decode(TrustServiceStatusList.self, from: jsonData)
                                            completion(trustServiceList)
                                            print("Decoded TSL version: \(trustServiceList.schemeInformation.tslVersionIdentifier)")
                                            print("Number of providers: \(trustServiceList.trustServiceProviders?.count)")
                                            
                                            for provider in trustServiceList.trustServiceProviders ?? [] {
                                                print("Provider: \(provider.tspName)")
                                                if let tradeName = provider.tspTradeName {
                                                    print("Trade Name: \(tradeName)")
                                                }
                                            }
                                        }
                                    } catch {
                                        completion(nil)
                                        print("Error decoding JSON: \(error)")
                                        
                                    }
                                }
//
                                
                            case .failure(let error):
                                completion(nil)
                                print("Error parsing XML to JSON: \(error)")
                            }
                        }
    
                }.resume()
    }
    
    
}
