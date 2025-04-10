//
//  File.swift
//
//
//  Created by iGrant on 02/12/24.
//

import Foundation
import Compression
import zlib

public class CredentialRevocationService {
    
    public init() {}
    
    public func getRevokedCredentials(credentialList: [String], keyHandler: SecureKeyProtocol) async ->  [String]{
        var statusList: [String] = []
        var statusList2021: [String] = []
        var revokedCredentials: [String] = []
        for item in credentialList {
            let split = item.split(separator: ".")
            if split.count > 1 {
                let jsonString = "\(split[1])".decodeBase64() ?? ""
                let dict = UIApplicationUtils.shared.convertStringToDictionary(text: jsonString)
                if let status = dict?["status"] as? [String: Any] {
                    statusList.append(item)
                }
                if let vc = dict?["vc"] as? [String: Any], let statusListArray = vc["credentialStatus"] as? [String: Any] {
                    statusList2021.append(item)
                }
            }
        }
        if !statusList.isEmpty {
            let revoked  = await IETFCredentialRevocationService().getRevokedCredentials(credentialList: statusList, keyHandler: keyHandler)
            revokedCredentials.append(contentsOf: revoked)
        }
        if !statusList2021.isEmpty {
            let revoked = await VerifiableCredentialRevocationService().getRevokedCredentials(credentialList: statusList2021, keyHandler: keyHandler)
            revokedCredentials.append(contentsOf: revoked)
        }
        return revokedCredentials
    }
    
}
