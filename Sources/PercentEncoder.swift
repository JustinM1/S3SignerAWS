import Core
import Bits

// MARK: - Allowed characters when calculating AWS Signatures.
extension Byte {
	internal static let awsQueryAllowed = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~=&".bytes
	
	internal static let awsPathAllowed  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~/".bytes
}

extension Collection where Iterator.Element == Byte {

    internal var string: String {
        return String(bytes: self, encoding: .utf8) ?? ""
    }
}

extension String {
    
    internal var bytes: [UInt8] {
        return Array(self.utf8)
    }
    
	internal func percentEncode(allowing allowed: Bytes) throws -> String {
		let bytes = self.bytes
		let encodedBytes = try percentEncodedUppercase(bytes, shouldEncode: {
			return !allowed.contains($0)
		})
		return encodedBytes.string
	}
	
	private func percentEncodedUppercase(
		_ input: [Byte],
		shouldEncode: (Byte) throws -> Bool = { _ in true }
		) throws -> [Byte] {
		var group: [Byte] = []
		try input.forEach { byte in
			if try shouldEncode(byte) {
				let hex = String(byte, radix: 16).uppercased().utf8
				group.append(.percent)
				if hex.count == 1 {
					group.append(.zero)
				}
				group.append(contentsOf: hex)
			} else {
				group.append(byte)
			}
		}
		return group
	}
}
