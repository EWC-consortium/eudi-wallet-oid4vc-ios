//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by oem on 18/06/25.
//

import Foundation
import SwiftCBOR
import OrderedCollections

public class MDocVpTokenBuilder : VpTokenBuilder{
    public init() {}
    
    func build(credentials: [String], presentationRequest: PresentationRequest?, did: String, index: Int?, keyHandler: SecureKeyProtocol) -> String? {
        
        var presentationDefinition :PresentationDefinitionModel? = nil
        do {
            presentationDefinition = try VerificationService.processPresentationDefinition(presentationRequest?.presentationDefinition)
        } catch {
            presentationDefinition = nil
        }
        
        var cborString: String = ""
        var base64StringWithoutPadding = ""
        var requestedParams: [String] = []
        var limitDisclosure: Bool = false
        var docFiltered: [Document] = []
        
        for (index, cred) in credentials.enumerated() {
            if !cred.contains(".") {
                if let issuerAuthData = getIssuerAuth(credential: cred), let cborNameSpace = getNameSpaces(credential: cred, inputDescriptor: presentationDefinition?.inputDescriptors?[index]) {
                    
                    if let fields = presentationDefinition?.inputDescriptors?[index].constraints?.fields {
                        for field in fields {
                            let components = field.path?.first?.components(separatedBy: ["[", "]", "'"])
                            
                            let filteredComponents = components?.filter { !$0.isEmpty }
                            
                            if let identifier = filteredComponents?.last {
                                requestedParams.append(String(identifier))
                            }
                        }
                    }
                    if presentationDefinition?.inputDescriptors?[index].constraints?.limitDisclosure == nil {
                        limitDisclosure = false
                    } else {
                        limitDisclosure = true
                    }
                    var nameSpaceData: CBOR? = nil
                    if limitDisclosure {
                        nameSpaceData = filterNameSpaces(nameSpacesValue: cborNameSpace, requestedParams: requestedParams)
                    } else {
                        nameSpaceData = cborNameSpace
                    }
                    var docType = ""
                    if let docTypeValue = getDocTypeFromIssuerAuth(cborData: issuerAuthData), !docTypeValue.isEmpty {
                        docType = docTypeValue
                    } else if let docTypeValue = presentationDefinition?.docType,  !docTypeValue.isEmpty {
                        docType = docTypeValue
                    }
                    docFiltered.append(contentsOf: [Document(docType: docType, issuerSigned: IssuerSigned(nameSpaces: nameSpaceData ?? nil, issuerAuth: issuerAuthData))])
                    
                    let documentsToAdd = docFiltered.count == 0 ? nil : docFiltered
                    let deviceResponseToSend = DeviceResponse(version: "1.0", documents: documentsToAdd,status: 0)
                    let responseDict = deviceResponseToSend.toDictionary()
                    if let cborData = encodeToCBOR(responseDict) {
                        cborString = Data(cborData.encode()).base64EncodedString()
                        
                        base64StringWithoutPadding = cborString.replacingOccurrences(of: "=", with: "") ?? ""
                        base64StringWithoutPadding = base64StringWithoutPadding.replacingOccurrences(of: "+", with: "-")
                        base64StringWithoutPadding = base64StringWithoutPadding.replacingOccurrences(of: "/", with: "_")
                        
                        print(Data(cborData.encode()).base64EncodedString())
                    } else {
                        print("Failed to encode data")
                    }
                }
            }
        }
        return base64StringWithoutPadding
    }
    
    public func getIssuerAuth(credential: String) -> CBOR? {
        if let data = Data(base64URLEncoded: credential) {
            do {
                let decodedCBOR = try CBOR.decode([UInt8](data))
                
                if let dictionary = decodedCBOR {
                    if let issuerAuthValue = dictionary[CBOR.utf8String("issuerAuth")] {
                        return issuerAuthValue
                    }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
                return nil
            }
        } else {
            print("Invalid base64 URL encoded credential.")
            return nil
        }
        
        return nil
    }
    
    func getNameSpaces(credential: String, inputDescriptor: InputDescriptor?) -> CBOR? {
        var requestedParams: [String] = []
        if let fields = inputDescriptor?.constraints?.fields {
            for field in fields {
                let components = field.path?.first?.components(separatedBy: ["[", "]", "'"])
                
                let filteredComponents = components?.filter { !$0.isEmpty }
                
                if let identifier = filteredComponents?.last {
                    requestedParams.append(String(identifier))
                }
            }
        }
        // Convert the base64 URL encoded credential to Data
        if let data = Data(base64URLEncoded: credential) {
            do {
                // Decode the CBOR data into a dictionary
                let decodedCBOR = try CBOR.decode([UInt8](data))
                
                if let dictionary = decodedCBOR {
                    // Check for the presence of "issuerAuth" in the dictionary
                    if let issuerAuthValue = dictionary[CBOR.utf8String("nameSpaces")] {
                        return issuerAuthValue // Return the issuerAuth value directly
                    }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
                return nil
            }
        } else {
            print("Invalid base64 URL encoded credential.")
            return nil
        }
        
        return nil // Return nil if "issuerAuth" is not found
    }
    
    public func filterNameSpaces(nameSpacesValue: CBOR, requestedParams: [String]) -> CBOR? {
        if case let CBOR.map(nameSpaces) = nameSpacesValue {
            var filteredNameSpaces: OrderedDictionary<CBOR, CBOR> = [:]
            print("printing nameSpaces cbor: \(nameSpaces)")
            for (key, namespaceValue) in nameSpaces {
                var valuesArray: [CBOR] = []
                
                if case let CBOR.array(orgValues) = namespaceValue {
                    for value in orgValues {
                        if case let CBOR.tagged(tag, taggedValue) = value, tag.rawValue == 24 {
                            if case let CBOR.byteString(byteString) = taggedValue {
                                let data = Data(byteString)
                                if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)),
                                   case let CBOR.map(decodedMap) = decodedInnerCBOR {
                                    if let identifier = decodedMap[CBOR.utf8String("elementIdentifier")],
                                       let value = decodedMap[CBOR.utf8String("elementValue")],
                                       case let CBOR.utf8String(identifierString) = identifier {
                                        if requestedParams.contains(identifierString) {
                                            valuesArray.append(CBOR.tagged(tag, CBOR.byteString(byteString)))
                                        }
                                    }
                                }
                            }
                        }
                    }
                    print("printing cbor attributes array: \(valuesArray)")

                }
                
                if !valuesArray.isEmpty {
                    print("printing cbor valuesArray array: \(valuesArray)")
                    filteredNameSpaces[key] = CBOR.array(valuesArray)
                }
            }
            print("printing cbor data array: \(filteredNameSpaces)")
            return CBOR.map(filteredNameSpaces)
        }
        
        return nil
    }
    
    func getDocTypeFromIssuerAuth(cborData: CBOR) -> String? {
        guard case let CBOR.array(elements) = cborData else {
            print("Expected CBOR array, but got something else.")
            return nil
        }
        var docType: String? = ""
        for element in elements {
            if case let CBOR.byteString(byteString) = element {
                if let nestedCBOR = try? CBOR.decode(byteString) {
                    if case let CBOR.tagged(tag, item) = nestedCBOR, tag.rawValue == 24 {
                        if case let CBOR.byteString(data) = item {
                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)) {
                                docType = extractDocType(cborData: decodedInnerCBOR )
                            } else {
                                print("Failed to decode inner ByteString under Tag 24.")
                            }
                        }
                    }
                } else {
                    print("Could not decode ByteString as CBOR, inspecting data directly.")
                    print("ByteString data: \(byteString)")
                }
            } else {
                print("Element: \(element)")
            }
        }
        return docType ?? ""
    }
    
    func extractDocType(cborData: CBOR) -> String? {
        guard case let CBOR.map(map) = cborData else {
            return nil
        }
        
        // Iterate over the map to find the key 'docType'
        for (key, value) in map {
            if case let CBOR.utf8String(keyString) = key, keyString == "docType" {
                if case let CBOR.utf8String(docTypeValue) = value {
                    return docTypeValue
                } else {
                    print("The value associated with 'docType' is not a string.")
                }
            }
        }
        
        print("docType not found in the CBOR map.")
        return nil
    }
    
    func encodeToCBOR(_ dict: [String: Any]) -> CBOR? {
        var cborMap: OrderedDictionary<CBOR, CBOR> = [:]
        
        for (key, value) in dict {
            let cborKey = CBOR.utf8String(key)
            
            // Handle different value types
            if let stringValue = value as? String {
                if stringValue == "NULL" {
                    cborMap[cborKey] = CBOR.null
                } else if stringValue.contains("ByteString") {
                    // Handle ByteString placeholder
                    cborMap[cborKey] = CBOR.byteString([0x01, 0x02, 0x03]) // Example ByteString, customize as needed
                } else {
                    cborMap[cborKey] = CBOR.utf8String(stringValue)
                }
            } else if let intValue = value as? Int {
                if intValue >= 0 {
                    cborMap[cborKey] = CBOR.unsignedInt(UInt64(intValue))
                } else {
                    cborMap[cborKey] = CBOR.negativeInt(UInt64(-1 - intValue))
                }
            } else if let floatValue = value as? Float {
                cborMap[cborKey] = CBOR.float(floatValue)
            } else if let doubleValue = value as? Double {
                cborMap[cborKey] = CBOR.double(doubleValue)
            } else if let boolValue = value as? Bool {
                cborMap[cborKey] = CBOR.boolean(boolValue)
            } else if let arrayValue = value as? [Any] {
                cborMap[cborKey] = encodeArrayToCBOR(arrayValue)
            } else if let dictValue = value as? [String: Any] {
                if let encodedDict = encodeToCBOR(dictValue) {
                    cborMap[cborKey] = encodedDict
                }
            } else if let cborValue = value as? SwiftCBOR.CBOR {
                // Handle CBOR types directly
                cborMap[cborKey] = cborValue
            } else if let customObject = value as? CustomCborConvertible {
                // Handle custom objects that conform to CustomCborConvertible
                cborMap[cborKey] = customObject.toCBOR()
            } else {
                print("Unsupported type for key: \(key)")
                return nil
            }
        }
        
        return CBOR.map(cborMap)
    }
    
    func encodeArrayToCBOR(_ array: [Any]) -> CBOR {
        var cborArray: [CBOR] = []
        
        for value in array {
            if let stringValue = value as? String {
                if stringValue == "NULL" {
                    cborArray.append(CBOR.null)
                } else if stringValue.contains("ByteString") {
                    cborArray.append(CBOR.byteString([0x01, 0x02, 0x03])) // Example ByteString
                } else {
                    cborArray.append(CBOR.utf8String(stringValue))
                }
            } else if let intValue = value as? Int {
                if intValue >= 0 {
                    cborArray.append(CBOR.unsignedInt(UInt64(intValue)))
                } else {
                    cborArray.append(CBOR.negativeInt(UInt64(-1 - intValue)))
                }
            } else if let floatValue = value as? Float {
                cborArray.append(CBOR.float(floatValue))
            } else if let boolValue = value as? Bool {
                cborArray.append(CBOR.boolean(boolValue))
            } else if let dictValue = value as? [String: Any], let encodedDict = encodeToCBOR(dictValue) {
                cborArray.append(encodedDict)
            } else if let subArray = value as? [Any] {
                cborArray.append(encodeArrayToCBOR(subArray))
            } else if let cborValue = value as? SwiftCBOR.CBOR {
                // Handle CBOR values directly
                cborArray.append(cborValue)
            } else if let customObject = value as? CustomCborConvertible {
                // Handle custom objects
                cborArray.append(customObject.toCBOR())
            } else {
                print("Unsupported type in array")
                return CBOR.null
            }
        }
        
        return CBOR.array(cborArray)
    }
    
    func convertCBORtoJson(credential: String) -> String? {
        if let data = Data(base64URLEncoded: credential) {
            do {
                let decodedCBOR = try CBOR.decode([UInt8](data))
                if let dictionary = decodedCBOR {
                    
                    if let nameSpacesValue = dictionary[CBOR.utf8String("nameSpaces")],
                       case let CBOR.map(nameSpaces) = nameSpacesValue {
                        
                        var resultDict: [String: [String: String]] = [:]
                        for (key, namespaceValue) in nameSpaces {
                            var valuesDict: [String: String] = [:]
                            if case let CBOR.array(orgValues) = namespaceValue {
                                for value in orgValues {
                                    if case let CBOR.tagged(tag, taggedValue) = value, tag.rawValue == 24 {
                                        if case let CBOR.byteString(byteString) = taggedValue {
                                            let data = Data(byteString)
                                            
                                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)),
                                               case let CBOR.map(decodedMap) = decodedInnerCBOR {
                                                if let identifier = decodedMap[CBOR.utf8String("elementIdentifier")],
                                                   let value = decodedMap[CBOR.utf8String("elementValue")],
                                                   case let CBOR.utf8String(identifierString) = identifier {
                                                    
                                                    valuesDict[identifierString] = cborToString(value)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            resultDict[cborToString(key)] = valuesDict
                        }
                        
                        // Convert the result dictionary to JSON
                        let jsonData = try JSONSerialization.data(withJSONObject: resultDict, options: .prettyPrinted)
                        let jsonString = String(data: jsonData, encoding: .utf8)
                        return jsonString?.replacingOccurrences(of: "\n", with: "")
                    } else {
                        print("Key 'nameSpaces' not found or not a valid map.")
                    }
                }
            } catch {
                print("Error decoding CBOR: \(error)")
            }
        }
        return nil
    }
    
    func cborToString(_ cbor: CBOR) -> String {
        switch cbor {
        case .utf8String(let stringValue):
            return stringValue
        case .unsignedInt(let uintValue):
            return String(uintValue)
        case .negativeInt(let intValue):
            return String(intValue)
        case .boolean(let boolValue):
            return String(boolValue)
        case .null:
            return "null"
        case .float(let floatValue):
            return String(floatValue)
        case .double(let doubleValue):
            return String(doubleValue)
        default:
            return "Unsupported CBOR type"
        }
    }
    
//    func convertCBORtoJson(credential: String) -> String? {
//        if let data = Data(base64URLEncoded: credential) {
//            do {
//                let decodedCBOR = try CBOR.decode([UInt8](data))
//                if let dictionary = decodedCBOR {
//
//                    if let nameSpacesValue = dictionary[CBOR.utf8String("nameSpaces")],
//                       case let CBOR.map(nameSpaces) = nameSpacesValue {
//
//                        var resultDict: [String: [String: String]] = [:]
//                        for (key, namespaceValue) in nameSpaces {
//                            var valuesDict: [String: String] = [:]
//                            if case let CBOR.array(orgValues) = namespaceValue {
//                                for value in orgValues {
//                                    if case let CBOR.tagged(tag, taggedValue) = value, tag.rawValue == 24 {
//                                        if case let CBOR.byteString(byteString) = taggedValue {
//                                            let data = Data(byteString)
//
//                                            if let decodedInnerCBOR = try? CBOR.decode([UInt8](data)),
//                                               case let CBOR.map(decodedMap) = decodedInnerCBOR {
//                                                if let identifier = decodedMap[CBOR.utf8String("elementIdentifier")],
//                                                   let value = decodedMap[CBOR.utf8String("elementValue")],
//                                                   case let CBOR.utf8String(identifierString) = identifier {
//
//                                                    valuesDict[identifierString] = cborToString(value)
//                                                }
//                                            }
//                                        }
//                                    }
//                                }
//                            }
//                            resultDict[cborToString(key)] = valuesDict
//                        }
//
//                        // Convert the result dictionary to JSON
//                        let jsonData = try JSONSerialization.data(withJSONObject: resultDict, options: .prettyPrinted)
//                        let jsonString = String(data: jsonData, encoding: .utf8)
//                        return jsonString?.replacingOccurrences(of: "\n", with: "")
//                    } else {
//                        print("Key 'nameSpaces' not found or not a valid map.")
//                    }
//                }
//            } catch {
//                print("Error decoding CBOR: \(error)")
//            }
//        }
//        return nil
//    }
}
