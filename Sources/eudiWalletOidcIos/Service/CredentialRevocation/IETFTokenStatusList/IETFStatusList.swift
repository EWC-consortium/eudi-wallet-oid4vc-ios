import Foundation
import zlib

class IETFStatusList {
    private var list: [UInt8]
    private let bits: Int
    private let divisor: Int
    var size: Int

    init(size: Int, bits: Int) {
        self.size = size
        self.bits = bits
        self.divisor = 8 / bits
        self.list = Array(repeating: 0, count: size / divisor)
    }

    static func fromEncoded(_ encoded: String, bits: Int = 1) -> IETFStatusList {
        let newInstance = IETFStatusList(size: 0, bits: bits)
        newInstance.decode(encoded)
        return newInstance
    }

    func decode(_ input: String) {
        let paddedInput = input.padding(toLength: ((input.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        let base64 = paddedInput
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
        guard let decodedData = Data(base64Encoded: base64) else {
            fatalError("Invalid Base64 string.")
        }
        guard let decompressedData = decompress(data: decodedData) else {
            fatalError("Decompression failed.")
        }
        self.list = Array(decompressedData) // Update the list with decompressed data
        self.size = self.list.count * divisor // Update the size based on decompressed data
        print("Decoded list size: \(self.size)") // Debug: Check the size
    }

    func get(_ pos: Int) -> Int {
        let rest = pos % divisor
        let floored = pos / divisor
        let shift = rest * bits
        let mask = ((1 << bits) - 1) << shift
        return Int((list[floored] & UInt8(mask)) >> shift)
    }
    
    func decodedValues() -> [Int] {
        var values = [Int]()
        for pos in 0..<size {
            values.append(get(pos))
        }
        return values
    }

    private func decompress(data: Data) -> Data? {
        var decompressed = Data()
        var stream = z_stream()
        stream.next_in = UnsafeMutablePointer<UInt8>(mutating: (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count))
        stream.avail_in = uint(data.count)

        guard inflateInit_(&stream, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return nil }

        let bufferSize = 4096
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
        defer { buffer.deallocate() }

        repeat {
            stream.next_out = buffer
            stream.avail_out = uint(bufferSize)

            let status = inflate(&stream, Z_NO_FLUSH)
            if status == Z_STREAM_END {
                decompressed.append(buffer, count: bufferSize - Int(stream.avail_out))
                break
            } else if status != Z_OK {
                inflateEnd(&stream)
                return nil
            }

            decompressed.append(buffer, count: bufferSize - Int(stream.avail_out))
        } while stream.avail_out == 0

        inflateEnd(&stream)
        return decompressed
    }
    
}
