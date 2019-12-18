import Foundation
import OpenCrypto

public class S3SignerAWS  {
    
    /// AWS Access Key
    private let accessKey: String
    
    /// The region where S3 bucket is located.
    public let region: Region
    
    /// AWS Secret Key
    private let secretKey: String
    
    /// AWS Security Token. Used to validate temporary credentials, such as those from an EC2 Instance's IAM role
    private let securityToken : String? //
    
    /// The service used in calculating the signature. Currently limited to s3, possible expansion to other services after testing.
    internal var service: String {
        return "s3"
    }
    
    /// Initializes a signer which works for either permanent credentials or temporary secrets
    ///
    /// - Parameters:
    ///   - accessKey: AWS Access Key
    ///   - secretKey: AWS Secret Key
    ///   - region: Which AWS region to sign against
    ///   - securityToken: Optional token used only with temporary credentials
    public init(accessKey: String,
                secretKey: String,
                region: Region,
                securityToken: String? = nil)
    {
        self.accessKey = accessKey
        self.secretKey = secretKey
        self.region = region
        self.securityToken = securityToken
    }
    
    /// Generate a V4 auth header for aws Requests.
    ///
    /// - Parameters:
    ///   - httpMethod: HTTP Method (GET, HEAD, PUT, POST, DELETE)
    ///   - urlString: Full URL String. Left for ability to customize whether a virtual hosted-style request i.e. "https://exampleBucket.s3.amazonaws.com" vs path-style request i.e. "https://s3.amazonaws.com/exampleBucket". Make sure to include url scheme i.e. https:// or signature will not be calculated properly.
    ///   - headers: Any additional headers you want incuded in the signature. All the required headers are created automatically.
    ///   - payload: The payload being sent with request
    /// - Returns: The required headers that need to be sent with request. Host, X-Amz-Date, Authorization
    ///			- If PUT request, Content-Length
    ///			- if PUT and pathExtension is available, Content-Type
    ///			- if PUT and not unsigned, Content-md5
    /// - Throws: S3SignerError
    public func authHeaderV4(
        httpMethod: HTTPMethod,
        urlString: String,
        headers: [String: String] = [:],
        payload: Payload)
        throws -> [String:String]
    {
        guard let url = URL(string: urlString) else {
            throw S3SignerError.badURL
        }
        
        let dates = getDates(date: Date())
        
        let bodyDigest = try payload.hashed()
        
        var updatedHeaders = updateHeaders(
            headers: headers,
            url: url,
            longDate: dates.long,
            bodyDigest: bodyDigest)
        
        if httpMethod == .put && payload.isData {
            updatedHeaders["content-md5"] = Data(Insecure.MD5.hash(data: [UInt8](payload.data))).base64EncodedString()
        }
        
        updatedHeaders["Authorization"] = try generateAuthHeader(
            httpMethod: httpMethod,
            url: url,
            headers: updatedHeaders,
            bodyDigest: bodyDigest,
            dates: dates)
        
        if httpMethod == .put {
            updatedHeaders["Content-Length"] = payload.size()
            
            if url.pathExtension != "" {
                updatedHeaders["Content-Type"] = url.pathExtension
            }
        }
        
        if payload.isUnsigned {
            updatedHeaders["x-amz-content-sha256"] = bodyDigest
        }
        
        return updatedHeaders
    }
    
    /// Generate a V4 pre-signed URL
    ///
    /// - Parameters:
    ///   - httpMethod: The method of request.
    ///   - urlString: Full URL String. Left for ability to customize whether a virtual hosted-style request i.e. "https://exampleBucket.s3.amazonaws.com" vs path-style request i.e. "https://s3.amazonaws.com/exampleBucket". Make sure to include url scheme i.e. https:// or signature will not be calculated properly.
    ///   - expiration: How long the URL is valid.
    ///   - headers: Any additional headers to be included with signature calculation.
    /// - Returns: Pre-signed URL string.
    /// - Throws: S3SignerError
    public func presignedURLV4(
        httpMethod: HTTPMethod,
        urlString: String,
        expiration: TimeFromNow,
        headers: [String:String])
        throws -> String
    {
        guard let url = URL(string: urlString) else {
            throw S3SignerError.badURL
        }
        
        let dates = getDates(date: Date())
        
        var updatedHeaders = headers
        
        updatedHeaders["Host"] = url.host ?? region.host
        
        let (canonRequest, fullURL) = try presignedURLCanonRequest(httpMethod: httpMethod, dates: dates, expiration: expiration, url: url, headers: updatedHeaders)
        
        let stringToSign = try createStringToSign(canonicalRequest: canonRequest, dates: dates)
        
        let signature = try createSignature(stringToSign: stringToSign, timeStampShort: dates.short)
        
        return fullURL.absoluteString.appending("&X-Amz-Signature=\(signature)")
    }
    
    internal func canonicalHeaders(
        headers: [String: String])
        -> String
    {
        let headerList = Array(headers.keys)
            .map { "\($0.lowercased()):\(headers[$0]!)" }
            .filter { $0 != "authorization" }
            .sorted(by: { $0.localizedCompare($1) == ComparisonResult.orderedAscending })
            .joined(separator: "\n")
            .appending("\n")
        
        return headerList
    }
    
    internal func createCanonicalRequest(
        httpMethod: HTTPMethod,
        url: URL,
        headers: [String: String],
        bodyDigest: String)
        throws -> String
    {
        return try [
            httpMethod.rawValue,
            path(url: url),
            query(url: url),
            canonicalHeaders(headers: headers),
            signedHeaders(headers: headers),
            bodyDigest
            ].joined(separator: "\n")
    }
    
    /// Create signature
    ///
    /// - Parameters:
    ///   - stringToSign: String to sign.
    ///   - timeStampShort: Short timestamp.
    /// - Returns: Signature.
    /// - Throws: HMAC error.
    internal func createSignature(
        stringToSign: String,
        timeStampShort: String)
        throws -> String
    {
        let dateKey = hmacSign(data: timeStampShort, key: Data("AWS4\(secretKey)".utf8))
        let dateRegionKey = hmacSign(data: region.value, key: dateKey)
        let dateRegionServiceKey = hmacSign(data: service, key: dateRegionKey)
        let signingKey = hmacSign(data: "aws4_request", key: dateRegionServiceKey)
        let signature = hmacSign(data: stringToSign, key: signingKey)
        
        return signature.hexEncodedString()
    }
    
    func hmacSign(data: String, key: Data) -> Data {
        let stringToSign = data.data(using: .utf8) ?? Data()
        let key = SymmetricKey(data: key)
        let hash = HMAC<SHA256>.authenticationCode(for: stringToSign,
                                                   using: key)
        
        return Data(hash)
    }
    
    /// Create the String To Sign portion of signature.
    ///
    /// - Parameters:
    ///   - canonicalRequest: The canonical request used.
    ///   - dates: The dates object containing short and long timestamps of request.
    /// - Returns: String to sign.
    /// - Throws: If hashing canonical request fails.
    internal func createStringToSign(
        canonicalRequest: String,
        dates: Dates)
        throws -> String
    {
        let canonRequestHash = [UInt8](Data(SHA256.hash(data: [UInt8](canonicalRequest.utf8)))).hexEncodedString()
        return ["AWS4-HMAC-SHA256",
                dates.long,
                credentialScope(timeStampShort: dates.short),
                canonRequestHash]
            .joined(separator: "\n")
    }
    
    /// Credential scope
    ///
    /// - Parameter timeStampShort: Short timestamp.
    /// - Returns: Credential Scope.
    private func credentialScope(
        timeStampShort: String)
        -> String
    {
        return  [
            timeStampShort,
            region.value,
            service, "aws4_request"
            ].joined(separator: "/")
    }
    
    /// Generate Auth Header for V4 Authorization Header request.
    ///
    /// - Parameters:
    ///   - httpMethod: The HTTPMethod of request.
    ///   - url: The URL of the request.
    ///   - headers: All headers used in signature calcuation.
    ///   - bodyDigest: The hashed payload of request.
    ///   - dates: The short and long timestamps of time of request.
    /// - Returns: Authorization header value.
    /// - Throws: S3SignerError
    internal func generateAuthHeader(
        httpMethod: HTTPMethod,
        url: URL,
        headers: [String:String],
        bodyDigest: String,
        dates: Dates)
        throws -> String
    {
        let canonicalRequestHex = try createCanonicalRequest(httpMethod: httpMethod, url: url, headers: headers, bodyDigest: bodyDigest)
        let stringToSign = try createStringToSign(canonicalRequest: canonicalRequestHex, dates: dates)
        let signature = try createSignature(stringToSign: stringToSign, timeStampShort: dates.short)
        return "AWS4-HMAC-SHA256 Credential=\(accessKey)/\(credentialScope(timeStampShort: dates.short)), SignedHeaders=\(signedHeaders(headers: headers)), Signature=\(signature)"
    }
    
    /// Instantiate Dates object containing the required date formats needed for signature calculation.
    ///
    /// - Parameter date: The date of request.
    /// - Returns: Dates object.
    internal func getDates(date: Date) -> Dates {
        return Dates(date: date)
    }
    
    /// The percent encoded path of request URL.
    ///
    /// - Parameter url: The URL of request.
    /// - Returns: Percent encoded path if not empty, or "/".
    /// - Throws: Encoding error.
    private func path(url: URL) throws -> String {
        if !url.path.isEmpty, let encodedPath = url.path.percentEncode(.pathAllowed) {
            return encodedPath
        }
        return "/"
    }
    
    /// The canonical request for Presigned URL requests.
    ///
    /// - Parameters:
    ///   - httpMethod: HTTPMethod of request.
    ///   - dates: Dates formatted for request.
    ///   - expiration: The period of time before URL expires.
    ///   - url: The URL of the request.
    ///   - headers: Headers used to sign and add to presigned URL.
    /// - Returns: Canonical request for pre-signed URL.
    /// - Throws: S3SignerError
    internal func presignedURLCanonRequest(
        httpMethod: HTTPMethod,
        dates: Dates,
        expiration: TimeFromNow,
        url: URL,
        headers: [String: String])
        throws -> (String, URL)
    {
        let credScope = credentialScope(timeStampShort: dates.short)
        let signHeaders = signedHeaders(headers: headers)

        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw S3SignerError.badURL
        }
        
        let defaultParams: [(name: String, value: String)] = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", "\(accessKey)/\(credScope)"),
            ("X-Amz-Date", "\(dates.long)"),
            ("X-Amz-Expires", "\(expiration.expiration)"),
            ("X-Amz-SignedHeaders", "\(signHeaders)")
        ]

        components.queryItems = ((components.queryItems ?? []) + defaultParams.map { URLQueryItem(name: $0.name, value: $0.value) })
            .sorted(by: { $0.name < $1.name })

        // This should never throw. 
        guard let url =  components.url else {
            throw S3SignerError.badURL
        }

        let encodedQuery = try query(url: url)
        components.percentEncodedQuery = encodedQuery

        guard let updatedURL = components.url else {
            throw S3SignerError.badURL
        }

        return try (
            [
                httpMethod.rawValue,
                path(url: updatedURL),
                encodedQuery,
                canonicalHeaders(headers: headers),
                signHeaders,
                "UNSIGNED-PAYLOAD"
                ].joined(separator: "\n"),
            updatedURL)
    }
    
    /// Encode and sort queryItems.
    ///
    /// - Parameter url: The URL for request containing the possible queryItems.
    /// - Returns: Encoded and sorted(By Key) queryItem String.
    /// - Throws: Encoding Error
    internal func query(url: URL) throws -> String {
        if let queryItems = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems {
            let encodedItems = queryItems.map { "\($0.name.percentEncode(.queryAllowed) ?? "")=\($0.value?.percentEncode(.queryAllowed) ?? "")" }
            return encodedItems.sorted().joined(separator: "&")
        }
        return ""
    }
    
    /// Signed headers
    ///
    /// - Parameter headers: Headers to sign.
    /// - Returns: Signed headers.
    private func signedHeaders(headers: [String: String]) -> String {
        let headerList = Array(headers.keys).map { $0.lowercased() }.filter { $0 != "authorization" }.sorted().joined(separator: ";")
        return headerList
    }
    
    /// Add the required headers to a V4 authorization header request.
    ///
    /// - Parameters:
    ///   - headers: Original headers to add the additional required headers to.
    ///   - url: The URL of the request.
    ///   - longDate: The formatted ISO date.
    ///   - bodyDigest: The payload hash of request.
    /// - Returns: Updated headers with additional required headers.
    internal func updateHeaders(
        headers: [String:String],
        url: URL,
        longDate: String,
        bodyDigest: String)
        -> [String:String]
    {
        var updatedHeaders = headers
        updatedHeaders["X-Amz-Date"] = longDate
        updatedHeaders["Host"] = url.host ?? region.host
        
        if bodyDigest != "UNSIGNED-PAYLOAD" && service == "s3" {
            updatedHeaders["x-amz-content-sha256"] = bodyDigest
        }
        // According to http://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html#RequestWithSTS
        if let token = securityToken {
            updatedHeaders["X-Amz-Security-Token"] = token
        }
        return updatedHeaders
    }
}
