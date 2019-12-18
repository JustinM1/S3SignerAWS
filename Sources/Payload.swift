import OpenCrypto
import Foundation

/// The Payload associated with a request.
///
/// - data: The data of the request.
/// - none: No payload is in the request. i.e. GET request.
/// - unsigned: The size of payload will not go into signature calcuation. Useful if size is unknown at time of signature creation. Less secure as the payload can be changed and the signature won't be effected.
public enum Payload {
    case data(Data)
    case none
    case unsigned
    
    internal var data: Data {
        switch self {
        case .data(let data):
            return data
        default:
            return "".data(using: .utf8) ?? Data()
        }
    }
    
    /// Hash the payload being sent to AWS.
    /// - Data: Hashed using SHA256
    /// - None: Guaranteed no payload being sent, requires an empty string SHA256.
    /// - Unsigned: Any size payload will be accepted, wasn't considered in part of the signature.
    ///
    /// - Returns: The hashed hexString.
    /// - Throws: Hash Error.
    internal func hashed() throws -> String {
        switch self {
        case .data, .none:
            return [UInt8](Data(SHA256.hash(data: data))).hexEncodedString()
        case .unsigned:
            return "UNSIGNED-PAYLOAD"
            
        }
    }
    
    internal var isData: Bool {
        switch self {
        case .data, .none:
            return true
        default:
            return false
        }
    }
    
    internal func size() -> String {
        switch self {
        case .data, .none:
            return self.data.count.description
        case .unsigned:
            return "UNSIGNED-PAYLOAD"
        }
    }
    
    internal var isUnsigned: Bool {
        switch self {
        case .unsigned:
            return true
        default:
            return false
        }
    }
}

// Copied from OpenCrypto for now because it's internal 
extension Collection where Element == UInt8 {
    func hexEncodedString(uppercase: Bool = false) -> String {
        return String(decoding: hexEncodedBytes(uppercase: uppercase), as: Unicode.UTF8.self)
    }

    func hexEncodedBytes(uppercase: Bool = false) -> [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(count * 2)

        let table: [UInt8]
        if uppercase {
            table = radix16table_uppercase
        } else {
            table = radix16table_lowercase
        }

        for byte in self {
            bytes.append(table[Int(byte / 16)])
            bytes.append(table[Int(byte % 16)])
        }

        return bytes
    }
}

fileprivate let radix16table_uppercase: [UInt8] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46
]

fileprivate let radix16table_lowercase: [UInt8] = [
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
]
