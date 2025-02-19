//
//  File.swift
//
//
//  Created by iGrant on 02/12/24.
//

import Foundation
import Compression
import zlib

public class CredentialRevocationUtil {
    
    public init() {}
    
    public func getRevokedCredentials(credentialList: [String], keyHandler: SecureKeyProtocol) async -> [String]{
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
                    let statusList = data.bitsArray?[statusIndex]
                    if statusList == 1 {
                        revokedCredentials.append(item)
                    }
                }
            }
        }
        return revokedCredentials
    }
    
    func getStatusDetailsFromStatusList(jwt: String?, keyHandler: SecureKeyProtocol) -> (String?, Int?) {
        guard let jwt = jwt else { return (nil, nil)}
        if jwt.contains(".") {
            let split = jwt.split(separator: ".")
            if split.count > 1 {
                let jsonString = "\(split[1])".decodeBase64() ?? ""
                let dict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
                guard let statusData = dict?["status"] as? [String: Any] else { return (nil, nil) }
                if let statusListDict = statusData["status_list"] as? [String: Any], let statusIndex = statusListDict["idx"] as? Int , let statusUri = statusListDict["uri"] as? String {
                    return (statusUri, statusIndex)
                }
            }
            return (nil, nil)
        } else {
            var verificationHandler : eudiWalletOidcIos.VerificationService?
            verificationHandler = eudiWalletOidcIos.VerificationService(keyhandler: keyHandler)
            guard let issuerAuth = verificationHandler?.getIssuerAuth(credential: jwt) else { return (nil, nil)}
            let index = verificationHandler?.getStatusListItemsFromCbor(cborData: issuerAuth).0
            let uri = verificationHandler?.getStatusListItemsFromCbor(cborData: issuerAuth).1
            return (uri, index)
        }
    }
    
    func fetchStatusModel(statusList: [String?]) async -> [StatusListModel]{
        var statusModel: [StatusListModel] = []
        for uri in statusList {
        guard let uri = uri, let url = URL(string: uri) else { return []}
            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            request.setValue("application/statuslist+jwt", forHTTPHeaderField: "Accept")
            do {
                let (data, _) = try await URLSession.shared.data(for: request)
                let stringData = String.init(data: data, encoding: .utf8)
                let split = stringData?.split(separator: ".")
                guard split?.count ?? 0 > 1 else { return [] }
                let jsonString = "\(split?[1] ?? "")".decodeBase64() ?? ""
                let statusDict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
                let statusListDict = statusDict?["status_list"] as? [String: Any]
                let bits = statusListDict?["bits"] as? Int
        guard let bits = bits else { return []}
                let lst = statusListDict?["lst"] as? String ?? ""
                let statusList = StatusList.fromEncoded(lst, bits: bits ?? 0)
                let bitsArray = statusList.decodedValues()
                let statusValues = StatusListModel(satausUri: uri, bitsArray: bitsArray)
                statusModel.append(statusValues)
            } catch {
                print("error")
            }
        }
        return statusModel
    }
    
}

struct StatusListModel {
    let satausUri: String?
    let bitsArray: [Int]?
}
