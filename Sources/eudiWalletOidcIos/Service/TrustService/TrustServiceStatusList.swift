//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 11/06/25.
//

import Foundation


public struct TrustServiceStatusList: Codable {
    public let schemeInformation: SchemeInformation
    public let trustServiceProviders: [TrustServiceProvider]?
}

public struct SchemeInformation: Codable {
    public var tslVersionIdentifier: Int
    public var tslSequenceNumber: Int
    public var tslType: String
    public var schemeOperatorName: String
    public var schemeName: String
    public var schemeTerritory: String
    public var listIssueDateTime: String
    public var nextUpdate: String
}

public struct TrustServiceProvider: Codable {
    public var tspName: String
    public var tspTradeName: String?
    public var tspInformationURI: String?
    public var tspAddress: TSPAddress?
    public var tspServices: [TSPService]
}

public struct TSPAddress: Codable {
    public var postalAddresses: [PostalAddress]?
    public var electronicAddresses: ElectronicAddress?
}

public struct PostalAddress: Codable {
    public  var streetAddress: String?
    public var locality: String?
    public var stateOrProvince: String?
    public var postalCode: String?
    public var countryName: String?
}

public struct ElectronicAddress: Codable {
    public var uri: String?
}

public struct TSPService: Codable {
    public var serviceTypeIdentifier: String
    public var serviceName: String
    public var serviceStatus: String
    public var statusStartingTime: String?
    public var serviceDigitalIdentities: [DigitalId]?
    public var serviceSupplyPoints: [String]?
}

public struct DigitalId: Codable {
    public var x509Certificate: String?
    public var x509SKI: String?
    public var x509SubjectName: String?
}

public class XMLToJSONParser: NSObject, XMLParserDelegate {
    private var currentElement = ""
    private var currentText = ""
    
    private var result: TrustServiceStatusList?
    private var schemeInformation: SchemeInformation?
    private var trustServiceProviders: [TrustServiceProvider] = []
    private var currentTSP: TrustServiceProvider?
    private var currentService: TSPService?
    private var currentDigitalId: DigitalId?
    private var currentAddress: TSPAddress?
    private var currentPostalAddress: PostalAddress?
    private var currentElectronicAddress: ElectronicAddress?
    
    private var currentNameContext: String? // "TSPName", "TSPTradeName", etc.
    private var currentNameLang: String?
    
    private var completion: ((Result<Data, Error>) -> Void)?
    
    func parse(xmlData: Data, completion: @escaping (Result<Data, Error>) -> Void) {
        self.completion = completion
        let parser = XMLParser(data: xmlData)
        parser.delegate = self
        parser.parse()
    }
    
    // MARK: - XMLParserDelegate
    
    public func parserDidStartDocument(_ parser: XMLParser) {
        trustServiceProviders = []
    }
    
    public func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String : String] = [:]) {
        currentElement = elementName
        currentText = ""
        
        if elementName == "Name" {
            currentNameLang = attributeDict["xml:lang"]
        }
        
        switch elementName {
        case "SchemeInformation":
            schemeInformation = SchemeInformation(
                tslVersionIdentifier: 0,
                tslSequenceNumber: 0,
                tslType: "",
                schemeOperatorName: "",
                schemeName: "",
                schemeTerritory: "",
                listIssueDateTime: "",
                nextUpdate: ""
            )
        case "TrustServiceProvider":
            currentTSP = TrustServiceProvider(
                tspName: "",
                tspTradeName: nil,
                tspInformationURI: nil,
                tspAddress: nil,
                tspServices: []
            )
        case "TSPService":
            currentService = TSPService(
                serviceTypeIdentifier: "",
                serviceName: "",
                serviceStatus: "",
                statusStartingTime: nil,
                serviceDigitalIdentities: [],
                serviceSupplyPoints: []
            )
        case "DigitalId":
            currentDigitalId = DigitalId(
                x509Certificate: nil,
                x509SKI: nil,
                x509SubjectName: nil
            )
        case "TSPAddress":
            currentAddress = TSPAddress(
                postalAddresses: [],
                electronicAddresses: nil
            )
        case "PostalAddress":
            currentPostalAddress = PostalAddress(
                streetAddress: nil,
                locality: nil,
                stateOrProvince: nil,
                postalCode: nil,
                countryName: nil
            )
        case "ElectronicAddress":
            currentElectronicAddress = ElectronicAddress(
                uri: nil
            )
        case "TSPName":
            currentNameContext = "TSPName"
        case "TSPTradeName":
            currentNameContext = "TSPTradeName"
        case "ServiceName":
            currentNameContext = "ServiceName"
        default:
            break
        }
    }
    
    public func parser(_ parser: XMLParser, foundCharacters string: String) {
        currentText += string.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    public func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
        switch elementName {
        case "Name":
            if currentNameLang == "en" || currentNameLang == nil {
                switch currentNameContext {
                case "TSPName":
                    currentTSP?.tspName = currentText
                case "TSPTradeName":
                    currentTSP?.tspTradeName = currentText.isEmpty ? nil : currentText
                case "ServiceName":
                    currentService?.serviceName = currentText
                case "SchemeOperatorName":
                    schemeInformation?.schemeOperatorName = currentText
                case "SchemeName":
                    schemeInformation?.schemeName = currentText
                default:
                    break
                }
            }
            currentNameContext = nil
            currentNameLang = nil
            
        case "TSLVersionIdentifier":
            schemeInformation?.tslVersionIdentifier = Int(currentText) ?? 0
        case "TSLSequenceNumber":
            schemeInformation?.tslSequenceNumber = Int(currentText) ?? 0
        case "TSLType":
            schemeInformation?.tslType = currentText
        case "SchemeTerritory":
            schemeInformation?.schemeTerritory = currentText
        case "ListIssueDateTime":
            schemeInformation?.listIssueDateTime = currentText
        case "dateTime" where currentElement == "NextUpdate":
            schemeInformation?.nextUpdate = currentText
            
        case "URI" where currentElement == "TSPInformationURI":
            currentTSP?.tspInformationURI = currentText.isEmpty ? nil : currentText
            
        case "StreetAddress":
            currentPostalAddress?.streetAddress = currentText.isEmpty ? nil : currentText
        case "Locality":
            currentPostalAddress?.locality = currentText.isEmpty ? nil : currentText
        case "StateOrProvince":
            currentPostalAddress?.stateOrProvince = currentText.isEmpty ? nil : currentText
        case "PostalCode":
            currentPostalAddress?.postalCode = currentText.isEmpty ? nil : currentText
        case "CountryName":
            currentPostalAddress?.countryName = currentText.isEmpty ? nil : currentText
            
        case "URI" where currentElement == "ElectronicAddress":
            currentElectronicAddress?.uri = currentText.isEmpty ? nil : currentText
            
        case "PostalAddress":
            if let postalAddress = currentPostalAddress {
                currentAddress?.postalAddresses?.append(postalAddress)
            }
            currentPostalAddress = nil
            
        case "ElectronicAddress":
            currentElectronicAddress?.uri = currentText
            if let electronicAddress = currentElectronicAddress {
                currentAddress?.electronicAddresses = electronicAddress
            }
            currentElectronicAddress = nil
            
        case "TSPAddress":
            currentTSP?.tspAddress = currentAddress
            currentAddress = nil
            
        case "ServiceTypeIdentifier":
            currentService?.serviceTypeIdentifier = currentText
        case "ServiceStatus":
            currentService?.serviceStatus = currentText
        case "StatusStartingTime":
            currentService?.statusStartingTime = currentText.isEmpty ? nil : currentText
            
        case "X509Certificate":
            currentDigitalId?.x509Certificate = currentText.isEmpty ? nil : currentText
        case "X509SKI":
            currentDigitalId?.x509SKI = currentText.isEmpty ? nil : currentText
        case "X509SubjectName":
            currentDigitalId?.x509SubjectName = currentText.isEmpty ? nil : currentText
            
        case "DigitalId":
            if let digitalId = currentDigitalId {
                currentService?.serviceDigitalIdentities?.append(digitalId)
            }
            currentDigitalId = nil
            
        case "ServiceSupplyPoint":
            currentService?.serviceSupplyPoints?.append(currentText)
            
        case "TSPService":
            if let service = currentService {
                currentTSP?.tspServices.append(service)
            }
            currentService = nil
            
        case "TrustServiceProvider":
            if let tsp = currentTSP {
                trustServiceProviders.append(tsp)
            }
            currentTSP = nil
            
        case "TrustServiceStatusList":
            if let schemeInfo = schemeInformation {
                result = TrustServiceStatusList(
                    schemeInformation: schemeInfo,
                    trustServiceProviders: trustServiceProviders
                )
                convertToJSON()
            }
            
        default:
            break
        }
    }
    
    private func convertToJSON() {
        guard let result = result else {
            completion?(.failure(NSError(domain: "", code: -1, userInfo: [NSLocalizedDescriptionKey: "Failed to parse XML"])))
            return
        }
        
        do {
            let jsonData = try JSONEncoder().encode(result)
            completion?(.success(jsonData))
        } catch {
            completion?(.failure(error))
        }
    }
    
    public func parser(_ parser: XMLParser, parseErrorOccurred parseError: Error) {
        completion?(.failure(parseError))
    }
}
                        
                        
                        
