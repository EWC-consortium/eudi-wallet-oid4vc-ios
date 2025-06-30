//Class implementing the high level key generation and signing of data
//using JOSESwift library for secure enclave

import Foundation
import Security
import JOSESwift


enum SecureEnclaveError: Error {
    case couldNotLoadKeyPair
    case couldNotGenerateKeyPair(description: String)
    case couldNotCreateSigner
    case couldNotCreateVerifier
}

class SecureEnclave {
    let keyPair: KeyPair

    init(privateKeyApplicationTag: String) {
        do {
            keyPair = try SecureEnclave.loadKeyPair(with: privateKeyApplicationTag)
        } catch {
            keyPair = try! SecureEnclave.generateKeyPair(with: privateKeyApplicationTag)
        }
    }

    //signing of data securely with the private key
    func sign(_ message: String, header: Data) throws -> String {
        if let headerParams = JWSHeader(header){
            let payload = Payload(message.data(using: .utf8)!)

            guard let signer = Signer(signatureAlgorithm: .ES256, key: keyPair.privateKey) else {
                throw SecureEnclaveError.couldNotCreateSigner
            }

            return try JWS(header: headerParams, payload: payload, signer: signer).compactSerializedString
        }else{
            throw SecureEnclaveError.couldNotCreateSigner
        }
    }

    func verify(_ compactSerialization: String) throws -> Bool {
        guard let verifier = Verifier(signatureAlgorithm: .ES256, key: keyPair.publicKey) else {
            throw SecureEnclaveError.couldNotCreateVerifier
        }

        let jws = try JWS(compactSerialization: compactSerialization)

        return jws.isValid(for: verifier)
    }

}

extension SecureEnclave {
    typealias KeyPair = (privateKey: SecKey, publicKey: SecKey)

    //Load the private and public keys if already available in secure enclave
    static func loadKeyPair(with applicationTag: String) throws -> KeyPair {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw SecureEnclaveError.couldNotLoadKeyPair
        }

        let privateKey = item as! SecKey
        let publicKey = SecKeyCopyPublicKey(privateKey)!

        return (privateKey, publicKey)
    }

    //generate new pair of public and private keys from secure enclave
    static func generateKeyPair(with applicationTag: String) throws -> KeyPair {
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        )!

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessControl as String: access
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw SecureEnclaveError.couldNotGenerateKeyPair(
                description: error!.takeRetainedValue().localizedDescription
            )
        }

        let publicKey = SecKeyCopyPublicKey(privateKey)!
        
        return (privateKey, publicKey)
    }
    
    //create jason web key for the given public key
    func getJWK(publicKey:Data) -> [String:Any]?{
        let jwk = try! ECPublicKey(publicKey: publicKey)
        if let jsonData = jwk.jsonData(){
            if let jwkDict = convertToDictionary(data: jsonData){
                return jwkDict
            }
        }
        return nil
    }
    
    func convertToDictionary(data: Data) -> [String: Any]? {
      
           do {
               return try JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
           } catch {
               print(error.localizedDescription)
           }
       
       return nil
   }
}
