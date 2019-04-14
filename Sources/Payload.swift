import Core
import Crypto
import Bits

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
            return "".convertToData()
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
            return try SHA256.hash(data).hexEncodedString()
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
