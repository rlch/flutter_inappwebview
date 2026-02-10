//
//  URLProtectionSpace.swift
//  flutter_inappwebview
//
//  Created by Lorenzo Pichilli on 19/02/21.
//

import Foundation

extension URLProtectionSpace {
    
    var x509Certificate: Data? {
        guard let serverTrust = serverTrust else {
            return nil
        }
        
        var error: CFError?
        _ = SecTrustEvaluateWithError(serverTrust, &error)

        if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
            return serverCertificate.data
        }
        return nil
    }
    
    var sslCertificate: SslCertificate? {
        var sslCertificate: SslCertificate? = nil
        if let x509Certificate = x509Certificate {
            sslCertificate = SslCertificate(x509Certificate: x509Certificate)
        }
        return sslCertificate
    }
    
    var sslError: SslError? {
        guard let serverTrust = serverTrust else {
            return nil
        }
        
        var error: CFError?
        _ = SecTrustEvaluateWithError(serverTrust, &error)
        var secResult = SecTrustResultType.invalid
        SecTrustGetTrustResult(serverTrust, &secResult)

        guard let sslErrorType = secResult != SecTrustResultType.proceed ? secResult : nil else {
            return nil
        }
        
        return SslError(errorType: sslErrorType)
    }
    
    public func toMap () -> [String:Any?] {
        return [
            "host": host,
            "protocol": self.protocol,
            "realm": realm,
            "port": port,
            "sslCertificate": sslCertificate?.toMap(),
            "sslError": sslError?.toMap(),
            "authenticationMethod": authenticationMethod,
            "distinguishedNames": distinguishedNames,
            "receivesCredentialSecurely": receivesCredentialSecurely,
            "proxyType": proxyType
        ]
    }
}
