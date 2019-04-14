import Foundation
@testable import S3SignerAWS

/// A way to inject specific required info for aws signing tests without introducing to S3SignerAWS.
class S3SignerTester: S3SignerAWS {
    
    var overridenDate: Dates?
    
    var overrideService: String = "service"
    
    override var service: String {
        return overrideService
    }
    
    override func getDates(date: Date) -> Dates {
        return overridenDate ?? Dates(date: date)
    }
}

extension Dates {
    init(longDate: String) {
        let short = String(longDate[..<String.Index(utf16Offset: 8, in: longDate)])
        self = Dates(long: longDate, short: short)
    }
}
