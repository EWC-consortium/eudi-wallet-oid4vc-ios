//
//  File.swift
//  eudiWalletOidcIos
//
//  Created by iGrant on 09/04/25.
//

import Foundation
import Gzip

public class VerifiableCredentialStatusList2021 {
    
    private var bitLength: Int = 0
    public var bitstring: [Character] = []

        init(encodedStr: String? = nil, sizeKB: Int = 16) {
            self.bitLength = sizeKB * 1024 * 8 // 16KB = 131072 bits

            if let encoded = encodedStr,
               let decompressedData = Self.decodeAndDecompress(encoded: encoded),
               let bitStr = Self.convertToBitstring(data: decompressedData) {
                self.bitstring = Array(bitStr)
            } else {
                self.bitstring = Array(repeating: "0", count: bitLength)
            }
        }

        // MARK: - Decode Base64 + Decompress (GZIP)
    private static func decodeAndDecompress(encoded: String) -> Data? {
        let padded = encoded.padding(toLength: ((encoded.count + 3) / 4) * 4, withPad: "=", startingAt: 0)

        // Decode base64 (URL-safe first, fallback to normal)
        let decodedData: Data?
        if let urlSafeData = Data(base64URLEncoded: encoded) {
            decodedData = urlSafeData
        } else {
            decodedData = Data(base64Encoded: encoded)
        }

        guard let data = decodedData else { return nil }

        // Try decompressing
        do {
            return try data.gunzipped()
        } catch {
            print("Decompression failed: \(error)")
            return nil
        }
    }

        // MARK: - Convert binary data to full bitstring
        private static func convertToBitstring(data: Data) -> String? {
            return data.map { String($0, radix: 2).leftPad(toLength: 8, withPad: "0") }.joined()
        }

        // MARK: - Public Bit Access
        func setBit(index: Int, value: Int) {
            guard (0..<bitLength).contains(index), value == 0 || value == 1 else {
                return
            }
            bitstring[index] = value == 1 ? "1" : "0"
        }

        func getBit(index: Int) -> Character {
            guard (0..<bitLength).contains(index) else {
                fatalError("Bit index out of range.")
            }
            return bitstring[index]
        }

}

extension String {
    func leftPad(toLength: Int, withPad character: Character) -> String {
        let paddingCount = max(0, toLength - self.count)
        return String(repeating: character, count: paddingCount) + self
    }
}
