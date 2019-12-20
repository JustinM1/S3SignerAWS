import Foundation

// MARK: - Allowed characters when calculating AWS Signatures.
enum AWSEncoding: String {
    case queryAllowed = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~=&"
    case pathAllowed = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~/"
}

extension String {
    
    internal func percentEncode(_ type: AWSEncoding) -> String? {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: type.rawValue)
        return addingPercentEncoding(withAllowedCharacters: allowed)
    }
}
