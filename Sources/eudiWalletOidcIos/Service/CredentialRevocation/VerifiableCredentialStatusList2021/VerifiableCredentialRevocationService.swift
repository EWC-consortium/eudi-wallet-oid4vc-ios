//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 09/04/25.
//

import Foundation

class VerifiableCredentialRevocationService: CredentialRevocationServiceProtocol {
    
    public func getRevokedCredentials(credentialList: [String], keyHandler: SecureKeyProtocol) async -> [String] {
        var revokedCredentials: [String] = []
        var statusList: [String] = []
        for item in credentialList {
            if let statusUri = getStatusDetailsFromStatusList(jwt: item, keyHandler: keyHandler).0 {
                statusList.append(statusUri)
            }
        }
        let uiniqueStatusListArray = Array(Set(statusList))
        let statusModelList = await fetchStatusModel(statusList: uiniqueStatusListArray)
        for item in credentialList {
            let statusIndex = getStatusDetailsFromStatusList(jwt: item, keyHandler: keyHandler).1 ?? 0
            let statusUri = getStatusDetailsFromStatusList(jwt: item, keyHandler: keyHandler).0
            for data in statusModelList {
                if statusUri == data.satausUri {
                    let statusIndexValue = data.bitsArray?[statusIndex]
                    if statusIndexValue as? Character == "1" {
                        revokedCredentials.append(item)
                    }
                }
            }
        }
        return revokedCredentials
    }
        
    func getStatusDetailsFromStatusList(jwt: String?, keyHandler: SecureKeyProtocol) -> (String?, Int?) {
        guard let jwt = jwt else { return (nil, nil)}
        let split = jwt.split(separator: ".")
        if split.count > 1 {
            let jsonString = "\(split[1])".decodeBase64() ?? ""
            let dict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
            guard let vc = dict?["vc"] as? [String: Any], let statusData = vc["credentialStatus"] as? [String: Any] else { return (nil, nil) }
            if let statusIndex = statusData["statusListIndex"] as? String , let statusUri = statusData["statusListCredential"] as? String {
                return (statusUri, Int(statusIndex))
            }
        }
        return (nil, nil)
    }
    
    func fetchStatusModel(statusList: [String?]) async -> [StatusListModel]{
        var statusModel: [StatusListModel] = []
        for uri in statusList {
            guard let uri = uri, let url = URL(string: uri) else { return []}
            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                let stringData = String.init(data: data, encoding: .utf8)
                let split = stringData?.split(separator: ".")
                guard split?.count ?? 0 > 1 else { return [] }
                let jsonString = "\(split?[1] ?? "")".decodeBase64() ?? ""
                let statusDict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
                let vc = statusDict?["vc"] as? [String: Any]
                let statusListDict = vc?["credentialSubject"] as? [String: Any]
                let encodedList = statusListDict?["encodedList"] as? String
                let statusList = VerifiableCredentialStatusList2021(encodedStr: encodedList)
                let bitsArray = statusList.bitstring
                let statusValues = StatusListModel(satausUri: uri, bitsArray: bitsArray)
                statusModel.append(statusValues)
            } catch {
                print("error")
            }
        }
        return statusModel
    }
    
    func fetchEncodedList(statusList: [String?]) async -> [String]{
        var encodedDataList: [String] = []
        for uri in statusList {
            guard let uri = uri, let url = URL(string: uri) else { return []}
            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                let stringData = String.init(data: data, encoding: .utf8)
                let split = stringData?.split(separator: ".")
                guard split?.count ?? 0 > 1 else { return [] }
                let jsonString = "\(split?[1] ?? "")".decodeBase64() ?? ""
                let statusDict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
                let vc = statusDict?["vc"] as? [String: Any]
                let statusListDict = vc?["credentialSubject"] as? [String: Any]
                let encodedList = statusListDict?["encodedList"] as? String
                encodedDataList.append(encodedList ?? "")
            } catch {
                print("error")
            }
        }
        return encodedDataList
    }
    
}
