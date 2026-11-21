package com.goreecloud.dns

import java.net.URI

// Only a trusted HTTPS origin, without user info, path, query or fragments.
// This fails closed before the API token is copied into a request header.
internal object EndpointPolicy {
    fun validate(input: String): String {
        val origin = input.trim().trimEnd('/')
        val uri = URI(origin)
        require(uri.scheme.equals("https", ignoreCase = true) &&
            !uri.isOpaque && !uri.host.isNullOrBlank() &&
            uri.rawUserInfo == null && (uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") &&
            uri.rawQuery == null && uri.rawFragment == null &&
            (uri.port == -1 || uri.port in 1..65535)) {
            "Enter a trusted HTTPS origin without credentials or URL parameters."
        }
        return origin
    }
}
